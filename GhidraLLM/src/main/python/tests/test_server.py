import pytest
import grpc
from unittest.mock import MagicMock, patch
from concurrent import futures
from ghidra_llm.server import GhidraLLMServicer, serve
from ghidra_llm import ghidra_llm_pb2 as pb2
from ghidra_llm import ghidra_llm_pb2_grpc as pb2_grpc

@pytest.fixture
def mock_llm_client():
    with patch('ghidra_llm.server.LLMClient') as mock:
        client = mock.return_value
        client.generate_response.return_value = "Test response"
        client.analyze_binary.return_value = "Test analysis"
        client.explain_code.return_value = "Test explanation"
        client.suggest_analysis.return_value = ["Step 1", "Step 2"]
        yield client

@pytest.fixture
def servicer(mock_llm_client):
    return GhidraLLMServicer(api_key="test_key")

def test_query_llm(servicer):
    request = pb2.QueryRequest(
        query="Test query",
        context="Test context",
        metadata={"key": "value"}
    )
    context = MagicMock()
    
    response = servicer.QueryLLM(request, context)
    assert response.response == "Test response"
    assert not context.set_code.called

def test_analyze_binary(servicer):
    request = pb2.BinaryAnalysisRequest(
        binary_path="test.exe",
        architecture="x86",
        entry_point=0x1000,
        sections=[
            pb2.Section(
                name=".text",
                start_address=0x1000,
                end_address=0x2000,
                permissions="r-x"
            )
        ],
        imports=[
            pb2.Import(
                name="printf",
                library="msvcrt.dll",
                address=0x3000
            )
        ],
        exports=[
            pb2.Export(
                name="main",
                address=0x1000,
                type="function"
            )
        ]
    )
    context = MagicMock()
    
    response = servicer.AnalyzeBinary(request, context)
    assert response.analysis == "Test analysis"
    assert not context.set_code.called

def test_explain_code(servicer):
    request = pb2.CodeExplanationRequest(
        code="mov eax, 0x1234",
        language="x86",
        context="Test context"
    )
    context = MagicMock()
    
    response = servicer.ExplainCode(request, context)
    assert response.explanation == "Test explanation"
    assert not context.set_code.called

def test_suggest_analysis(servicer):
    request = pb2.AnalysisSuggestionRequest(
        current_analysis="Test analysis",
        completed_steps=["Step 1", "Step 2"],
        findings={"key": "value"}
    )
    context = MagicMock()
    
    response = servicer.SuggestAnalysis(request, context)
    assert response.suggested_steps == ["Step 1", "Step 2"]
    assert not context.set_code.called

def test_error_handling(servicer, mock_llm_client):
    mock_llm_client.generate_response.side_effect = Exception("Test error")
    request = pb2.QueryRequest(query="Test query")
    context = MagicMock()
    
    response = servicer.QueryLLM(request, context)
    assert not response.response
    assert context.set_code.called
    assert context.set_details.called

@pytest.mark.asyncio
async def test_server_startup():
    with patch('grpc.server') as mock_server:
        mock_server.return_value.start = MagicMock()
        mock_server.return_value.wait_for_termination = MagicMock()
        
        serve(port=50051)
        
        assert mock_server.called
        assert mock_server.return_value.start.called
        assert mock_server.return_value.wait_for_termination.called 