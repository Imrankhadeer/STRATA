import re
from pathlib import Path
from bs4 import BeautifulSoup
import pytest

DOC_PATH = Path("documentation.html")

def test_documentation_file_exists():
    assert DOC_PATH.exists(), "documentation.html must exist"

def test_documentation_anchors_and_links():
    html = DOC_PATH.read_text(encoding="utf-8")
    soup = BeautifulSoup(html, "html.parser")
    
    # Collect all IDs defined in the document
    defined_ids = {tag["id"] for tag in soup.find_all(id=True)}
    
    # Collect all internal hash links (<a href="#...">)
    internal_links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("#") and len(href) > 1:
            internal_links.append(href[1:])
            
    # Check that every internal link resolves to an ID in the document
    missing_targets = [target for target in internal_links if target not in defined_ids]
    assert not missing_targets, f"Found internal links to non-existent IDs: {set(missing_targets)}"

def test_tutorial_anchors_present():
    html = DOC_PATH.read_text(encoding="utf-8")
    soup = BeautifulSoup(html, "html.parser")
    defined_ids = {tag["id"] for tag in soup.find_all(id=True)}
    
    required_tutorial_ids = [
        "tutorial",
        "mental-model",
        "tutorial-step1",
        "tutorial-step2",
        "tutorial-step3",
        "tutorial-step4",
        "tutorial-step5",
    ]
    for tid in required_tutorial_ids:
        assert tid in defined_ids, f"Required tutorial ID '{tid}' missing in documentation.html"

def test_no_hardcoded_secrets_in_docs():
    html = DOC_PATH.read_text(encoding="utf-8")
    # Must not contain actual development secret key values or real tokens
    assert "ce_live_test_api_key_secret_12345" not in html, "Hardcoded test key found in documentation.html"
    assert "LLM_" not in html, "Hardcoded LLM key prefix found in documentation.html"
    # Ensure placeholder is used
    assert "YOUR_TERNLINE_API_KEY" in html, "Standard placeholder YOUR_TERNLINE_API_KEY expected"

def test_client_imports_are_accurate():
    html = DOC_PATH.read_text(encoding="utf-8")
    # Must not contain fictional client imports
    assert "TernlineClient" not in html, "Fictional TernlineClient import found in docs"
    assert "from cyber_engine import CyberEngine" in html, "Canonical CyberEngine SDK import must be documented"

