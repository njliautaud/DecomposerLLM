import os
import grpc
import logging
from concurrent import futures
from typing import Optional
import ghidra_llm_pb2 as pb2
import ghidra_llm_pb2_grpc as pb2_grpc
from .llm_client import LLMClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GhidraLLMServicer(pb2_grpc.GhidraLLMServicer):
    def __init__(self, api_key=None):
        """Initialize the servicer with an LLM client."""
        self.llm_client = LLMClient(api_key=api_key)

    def QueryLLM(self, request, context):
        """Handle LLM query requests."""
        try:
            response = self.llm_client.generate_response(
                request.query,
                request.context,
                request.metadata
            )
            return pb2.QueryResponse(response=response)
        except Exception as e:
            logger.error(f"Error in QueryLLM: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pb2.QueryResponse()

    def AnalyzeBinary(self, request, context):
        """Handle binary analysis requests."""
        try:
            analysis = self.llm_client.analyze_binary(
                request.binary_path,
                request.architecture,
                request.entry_point,
                request.sections,
                request.imports,
                request.exports
            )
            return pb2.BinaryAnalysisResponse(analysis=analysis)
        except Exception as e:
            logger.error(f"Error in AnalyzeBinary: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pb2.BinaryAnalysisResponse()

    def ExplainCode(self, request, context):
        """Handle code explanation requests."""
        try:
            explanation = self.llm_client.explain_code(
                request.code,
                request.language,
                request.context
            )
            return pb2.CodeExplanationResponse(explanation=explanation)
        except Exception as e:
            logger.error(f"Error in ExplainCode: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pb2.CodeExplanationResponse()

    def SuggestAnalysis(self, request, context):
        """Handle analysis suggestion requests."""
        try:
            suggestions = self.llm_client.suggest_analysis(
                request.current_analysis,
                request.completed_steps,
                request.findings
            )
            return pb2.AnalysisSuggestionResponse(suggested_steps=suggestions)
        except Exception as e:
            logger.error(f"Error in SuggestAnalysis: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pb2.AnalysisSuggestionResponse()

def serve(port=50051):
    """Start the gRPC server."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_GhidraLLMServicer_to_server(
        GhidraLLMServicer(api_key=os.getenv('GOOGLE_API_KEY')),
        server
    )
    server.add_insecure_port(f'[::]:{port}')
    server.start()
    logger.info(f"Server started on port {port}")
    server.wait_for_termination()

if __name__ == '__main__':
    serve() 