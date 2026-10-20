"""Synthetic placeholder; no production app-specific business scenarios."""


def business_scenario(rubric, index=0):
    return {
        "id": f"demo-{rubric['app_id']}-{index}",
        "name": "Synthetic request", "version": "demo-placeholder-v1",
        "execution_boundary": "text_only",
        "expected_visible": "Clarify the request without claiming real tool execution.",
        "messages": {
            "inputs": "Please outline the information needed for a fictional product inquiry. Do not execute tools.",
            "missing": "The product is fictional and no real customer record exists.",
            "boundary": "Keep the response textual; do not create or modify records.",
            "output": "List known requirements and missing information.",
            "stop": "Stop here without making external changes.",
        },
    }
