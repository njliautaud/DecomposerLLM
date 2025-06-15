import os
import pytest
from unittest.mock import MagicMock, patch
from ghidra_llm.client import LLMClient, BinaryAnalysisRequest, CodeExplanationRequest, AnalysisSuggestionRequest

@pytest.fixture
def mock_genai():
    with patch('google.generativeai') as mock:
        mock.GenerativeModel.return_value.generate_content.return_value.text = "Test response"
        yield mock

@pytest.fixture
def client(mock_genai):
    return LLMClient(api_key="test_key")

def test_generate_response(client):
    response = client.generate_response(
        query="Test query",
        context="Test context",
        metadata={"key": "value"}
    )
    assert response == "Test response"

def test_analyze_binary(client):
    request = BinaryAnalysisRequest(
        binary_path="test.exe",
        architecture="x86",
        entry_point=0x1000,
        sections=[{
            'name': '.text',
            'start_address': 0x1000,
            'end_address': 0x2000,
            'permissions': 'r-x'
        }],
        imports=[{
            'name': 'printf',
            'library': 'msvcrt.dll',
            'address': 0x3000
        }],
        exports=[{
            'name': 'main',
            'address': 0x1000,
            'type': 'function'
        }]
    )
    
    response = client.analyze_binary(request)
    assert response == "Test response"

def test_explain_code(client):
    request = CodeExplanationRequest(
        code="mov eax, 0x1234",
        language="x86",
        context="Test context"
    )
    
    response = client.explain_code(request)
    assert response == "Test response"

def test_suggest_analysis(client):
    request = AnalysisSuggestionRequest(
        current_analysis="Test analysis",
        completed_steps=["Step 1", "Step 2"],
        findings={"key": "value"}
    )
    
    response = client.suggest_analysis(request)
    assert isinstance(response, list)
    assert len(response) > 0

def test_missing_api_key():
    with pytest.raises(ValueError):
        LLMClient(api_key=None)

def test_format_sections(client):
    sections = [{
        'name': '.text',
        'start_address': 0x1000,
        'end_address': 0x2000,
        'permissions': 'r-x'
    }]
    
    formatted = client._format_sections(sections)
    assert ".text: 0x1000-0x2000 (r-x)" in formatted

def test_format_imports(client):
    imports = [{
        'name': 'printf',
        'library': 'msvcrt.dll',
        'address': 0x3000
    }]
    
    formatted = client._format_imports(imports)
    assert "printf from msvcrt.dll at 0x3000" in formatted

def test_format_exports(client):
    exports = [{
        'name': 'main',
        'address': 0x1000,
        'type': 'function'
    }]
    
    formatted = client._format_exports(exports)
    assert "main at 0x1000 (function)" in formatted 