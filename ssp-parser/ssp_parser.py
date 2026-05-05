#!/usr/bin/env python3
"""
OpenFRAMP SSP Parser — Extracts control implementations from FedRAMP SSP Appendix A.

Takes a FedRAMP SSP Appendix A .docx file and outputs structured JSON
containing every control's summary info and implementation statements.

Usage:
    python3 ssp_parser.py <path-to-appendix-a.docx> [--output results.json]
"""

import json
import re
import sys
from docx import Document


# Pattern to match control IDs like AC-1, AC-2, AU-2(1), SC-28(1)
CONTROL_ID_PATTERN = re.compile(r'^([A-Z]{2}-\d+(?:\(\d+\))?)\s')


def parse_summary_table(table):
    """Extract fields from a control summary table."""
    summary = {
        "control_id": "",
        "responsible_role": "",
        "parameters": {},
        "implementation_status": "",
        "control_origination": ""
    }
    
    for row in table.rows:
        cell_text = row.cells[0].text.strip()
        
        # Control ID from header row
        if "Control Summary Information" in cell_text:
            match = CONTROL_ID_PATTERN.match(cell_text)
            if match:
                summary["control_id"] = match.group(1)
        
        # Responsible role — the value is in the second column if it exists
        elif cell_text.startswith("Responsible Role"):
            if len(row.cells) > 1:
                summary["responsible_role"] = row.cells[1].text.strip()
            else:
                # Value might be after the colon in the same cell
                parts = cell_text.split(":", 1)
                if len(parts) > 1:
                    summary["responsible_role"] = parts[1].strip()
        
        # Parameters
        elif cell_text.startswith("Parameter"):
            param_match = re.match(r'Parameter\s+([^:]+):', cell_text)
            if param_match:
                param_name = param_match.group(1).strip()
                # Value is either after the colon or in the next cell
                if len(row.cells) > 1:
                    value = row.cells[1].text.strip()
                else:
                    parts = cell_text.split(":", 1)
                    value = parts[1].strip() if len(parts) > 1 else ""
                summary["parameters"][param_name] = value
        
        # Implementation status
        elif "Implementation Status" in cell_text:
            summary["implementation_status"] = cell_text
        
        # Control origination
        elif "Control Origination" in cell_text:
            summary["control_origination"] = cell_text
    
    return summary


def parse_implementation_table(table):
    """Extract implementation parts from a control implementation table."""
    implementation = {
        "control_id": "",
        "parts": {}
    }
    
    for row in table.rows:
        cell_text = row.cells[0].text.strip()
        
        # Control ID from header row
        if "What is the solution" in cell_text:
            match = CONTROL_ID_PATTERN.match(cell_text)
            if match:
                implementation["control_id"] = match.group(1)
        
        # Implementation parts (Part a:, Part b:, etc.)
        elif cell_text.startswith("Part "):
            part_match = re.match(r'Part\s+([a-z]):', cell_text)
            if part_match:
                part_letter = part_match.group(1)
                # The narrative is either after "Part X:" in the same cell
                # or in the second column
                if len(row.cells) > 1:
                    narrative = row.cells[1].text.strip()
                else:
                    parts = cell_text.split(":", 1)
                    narrative = parts[1].strip() if len(parts) > 1 else ""
                implementation["parts"][part_letter] = narrative
    
    return implementation


def parse_appendix_a(docx_path):
    """Parse a FedRAMP SSP Appendix A document and extract all controls."""
    print(f"Loading {docx_path}...")
    doc = Document(docx_path)
    print(f"Found {len(doc.tables)} tables")
    
    controls = {}
    
    for i, table in enumerate(doc.tables):
        first_cell = table.rows[0].cells[0].text.strip() if table.rows else ""
        
        # Summary table
        if "Control Summary Information" in first_cell:
            summary = parse_summary_table(table)
            cid = summary["control_id"]
            if cid:
                if cid not in controls:
                    controls[cid] = {"summary": {}, "implementation": {}}
                controls[cid]["summary"] = summary
        
        # Implementation table
        elif "What is the solution" in first_cell:
            impl = parse_implementation_table(table)
            cid = impl["control_id"]
            if cid:
                if cid not in controls:
                    controls[cid] = {"summary": {}, "implementation": {}}
                controls[cid]["implementation"] = impl
    
    return controls


def build_output(controls):
    """Build the final structured output."""
    output = {
        "parser_version": "1.0.0",
        "source": "FedRAMP SSP Appendix A",
        "total_controls": len(controls),
        "controls": []
    }
    
    for cid in sorted(controls.keys(), key=lambda x: (x.split("-")[0], int(re.search(r'\d+', x.split("-")[1]).group()))):
        ctrl = controls[cid]
        summary = ctrl.get("summary", {})
        impl = ctrl.get("implementation", {})
        
        # Count how many parts have actual content
        filled_parts = sum(1 for v in impl.get("parts", {}).values() if v)
        total_parts = len(impl.get("parts", {}))
        
        entry = {
            "control_id": cid,
            "responsible_role": summary.get("responsible_role", ""),
            "parameters": summary.get("parameters", {}),
            "implementation_status": summary.get("implementation_status", ""),
            "control_origination": summary.get("control_origination", ""),
            "implementation_parts": impl.get("parts", {}),
            "completeness": {
                "filled_parts": filled_parts,
                "total_parts": total_parts,
                "complete": filled_parts == total_parts and total_parts > 0
            }
        }
        output["controls"].append(entry)
    
    # Summary statistics
    total = len(output["controls"])
    complete = sum(1 for c in output["controls"] if c["completeness"]["complete"])
    has_content = sum(1 for c in output["controls"] if c["completeness"]["filled_parts"] > 0)
    
    output["statistics"] = {
        "total_controls": total,
        "controls_with_content": has_content,
        "fully_complete": complete,
        "empty": total - has_content,
        "completion_rate": f"{(has_content / total * 100):.1f}%" if total > 0 else "0%"
    }
    
    return output


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ssp_parser.py <appendix-a.docx> [--output results.json]")
        print()
        print("Example:")
        print("  python3 ssp_parser.py SSP-Appendix-A-Moderate-FedRAMP-Security-Controls.docx")
        sys.exit(1)
    
    docx_path = sys.argv[1]
    output_path = "ssp-parsed.json"
    
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_path = sys.argv[idx + 1]
    
    # Parse
    controls = parse_appendix_a(docx_path)
    
    # Build output
    output = build_output(controls)
    
    # Write JSON
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    
    # Print summary
    stats = output["statistics"]
    print()
    print("=" * 60)
    print("SSP Parser Results")
    print("=" * 60)
    print(f"Controls found:        {stats['total_controls']}")
    print(f"With content:          {stats['controls_with_content']}")
    print(f"Fully complete:        {stats['fully_complete']}")
    print(f"Empty (template only): {stats['empty']}")
    print(f"Completion rate:       {stats['completion_rate']}")
    print(f"Output:                {output_path}")
    print("=" * 60)
    
    # Show first 3 controls as preview
    print()
    print("Preview (first 3 controls):")
    for ctrl in output["controls"][:3]:
        parts_count = ctrl["completeness"]["total_parts"]
        filled = ctrl["completeness"]["filled_parts"]
        print(f"  {ctrl['control_id']}: {parts_count} parts ({filled} filled)")
        for letter, text in list(ctrl["implementation_parts"].items())[:2]:
            preview = text[:60] + "..." if len(text) > 60 else text
            preview = preview if preview else "(empty)"
            print(f"    Part {letter}: {preview}")


if __name__ == "__main__":
    main()
