"""
LLM Client for Ghidra Integration
"""

import os
import google.generativeai as genai
from langchain.agents import Tool, AgentExecutor, LLMSingleActionAgent
from langchain.prompts import StringPromptTemplate
from langchain.schema import AgentAction, AgentFinish
from typing import List, Union, Tuple
import re

class GhidraLLMClient:
    def __init__(self, api_key: str = None):
        """Initialize the LLM client with Google's Gemini API."""
        if api_key is None:
            api_key = os.getenv("GOOGLE_API_KEY")
            if api_key is None:
                raise ValueError("Google API key must be provided or set in GOOGLE_API_KEY environment variable")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        
    def generate_response(self, query: str, context: str = None) -> str:
        """Generate a response from the LLM based on the query and context."""
        prompt = f"Context: {context}\n\nQuery: {query}" if context else query
        response = self.model.generate_content(prompt)
        return response.text

    def analyze_binary(self, binary_info: dict) -> str:
        """Analyze binary information using the LLM."""
        prompt = f"""
        Analyze the following binary information and provide insights:
        
        Architecture: {binary_info.get('architecture', 'Unknown')}
        Entry Point: {binary_info.get('entry_point', 'Unknown')}
        Sections: {binary_info.get('sections', [])}
        Imports: {binary_info.get('imports', [])}
        Exports: {binary_info.get('exports', [])}
        
        Please provide:
        1. A high-level overview of the binary
        2. Potential functionality based on imports/exports
        3. Any security concerns or interesting patterns
        4. Suggestions for further analysis
        """
        
        return self.generate_response(prompt)

    def suggest_analysis(self, current_analysis: dict) -> str:
        """Suggest next steps in analysis based on current findings."""
        prompt = f"""
        Based on the current analysis:
        
        {current_analysis}
        
        Please suggest:
        1. Next areas to investigate
        2. Potential vulnerabilities to check
        3. Interesting functions to analyze
        4. Tools or techniques that might be helpful
        """
        
        return self.generate_response(prompt)

    def explain_code(self, code: str, context: str = None) -> str:
        """Explain a piece of code or assembly."""
        prompt = f"""
        Please explain the following code/assembly:
        
        {code}
        
        Additional Context:
        {context if context else 'None provided'}
        
        Please provide:
        1. A high-level explanation of what the code does
        2. Key operations and their purposes
        3. Any interesting patterns or techniques used
        4. Potential security implications
        """
        
        return self.generate_response(prompt)

    def suggest_improvements(self, code: str, current_analysis: dict) -> str:
        """Suggest improvements or optimizations for the code."""
        prompt = f"""
        Based on the current code and analysis:
        
        Code:
        {code}
        
        Current Analysis:
        {current_analysis}
        
        Please suggest:
        1. Potential optimizations
        2. Security improvements
        3. Code structure improvements
        4. Alternative approaches
        """
        
        return self.generate_response(prompt) 