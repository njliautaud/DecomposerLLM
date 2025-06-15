import os
import google.generativeai as genai
from typing import List, Dict, Optional
from dataclasses import dataclass
from . import ghidra_llm_pb2 as pb2

@dataclass
class BinaryAnalysisRequest:
    binary_path: str
    architecture: str
    entry_point: int
    sections: List[Dict]
    imports: List[Dict]
    exports: List[Dict]

@dataclass
class CodeExplanationRequest:
    code: str
    language: str
    context: str

@dataclass
class AnalysisSuggestionRequest:
    current_analysis: str
    completed_steps: List[str]
    findings: Dict[str, str]

class LLMClient:
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the LLM client with Google's Gemini API."""
        self.api_key = api_key or os.getenv('GOOGLE_API_KEY')
        if not self.api_key:
            raise ValueError("Google API key must be provided or set in GOOGLE_API_KEY environment variable")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-pro')

    def generate_response(self, query: str, context: str = "", metadata: Dict[str, str] = None) -> str:
        """Generate a response from the LLM based on a query and context."""
        prompt = f"Context: {context}\n\nQuery: {query}"
        if metadata:
            prompt += f"\n\nAdditional Information: {metadata}"
        
        response = self.model.generate_content(prompt)
        return response.text

    def analyze_binary(self, request: BinaryAnalysisRequest) -> str:
        """Analyze a binary using the LLM."""
        prompt = f"""Analyze the following binary:
Path: {request.binary_path}
Architecture: {request.architecture}
Entry Point: 0x{request.entry_point:x}

Sections:
{self._format_sections(request.sections)}

Imports:
{self._format_imports(request.imports)}

Exports:
{self._format_exports(request.exports)}

Please provide:
1. A high-level overview of the binary
2. Potential security concerns
3. Suggested analysis steps
4. Interesting functions or areas to investigate
"""
        response = self.model.generate_content(prompt)
        return response.text

    def explain_code(self, request: CodeExplanationRequest) -> str:
        """Get an explanation of code from the LLM."""
        prompt = f"""Explain the following {request.language} code:
Context: {request.context}

Code:
{request.code}

Please provide:
1. A detailed explanation of what the code does
2. Key concepts and techniques used
3. Potential security implications
4. Any interesting patterns or anti-analysis techniques
"""
        response = self.model.generate_content(prompt)
        return response.text

    def suggest_analysis(self, request: AnalysisSuggestionRequest) -> List[str]:
        """Get analysis suggestions from the LLM."""
        prompt = f"""Based on the current analysis:
Program: {request.current_analysis}

Completed Steps:
{self._format_list(request.completed_steps)}

Findings:
{self._format_dict(request.findings)}

Please suggest the next steps for analysis, focusing on:
1. Areas that need deeper investigation
2. Potential vulnerabilities to check
3. Interesting patterns to look for
4. Tools or techniques to apply
"""
        response = self.model.generate_content(prompt)
        return [step.strip() for step in response.text.split('\n') if step.strip()]

    def _format_sections(self, sections: List[Dict]) -> str:
        return '\n'.join(f"- {s['name']}: 0x{s['start_address']:x}-0x{s['end_address']:x} ({s['permissions']})"
                        for s in sections)

    def _format_imports(self, imports: List[Dict]) -> str:
        return '\n'.join(f"- {imp['name']} from {imp['library']} at 0x{imp['address']:x}"
                        for imp in imports)

    def _format_exports(self, exports: List[Dict]) -> str:
        return '\n'.join(f"- {exp['name']} at 0x{exp['address']:x} ({exp['type']})"
                        for exp in exports)

    def _format_list(self, items: List[str]) -> str:
        return '\n'.join(f"- {item}" for item in items)

    def _format_dict(self, items: Dict[str, str]) -> str:
        return '\n'.join(f"- {key}: {value}" for key, value in items.items()) 