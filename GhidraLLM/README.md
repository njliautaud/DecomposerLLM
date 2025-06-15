# Ghidra LLM Integration

This project integrates Google's Gemini LLM with Ghidra to provide AI-powered binary analysis capabilities. The integration allows Ghidra to leverage the power of large language models for tasks such as:

- Binary analysis and understanding
- Code explanation and documentation
- Analysis suggestions and guidance
- Vulnerability detection and assessment

## Prerequisites

- Ghidra 10.3 or later
- Python 3.8 or later
- Google Cloud API key for Gemini
- Protocol Buffers compiler (protoc)

## Installation

1. Clone this repository into your Ghidra plugins directory:
   ```bash
   git clone https://github.com/yourusername/GhidraLLM.git
   ```

2. Install Python dependencies:
   ```bash
   cd GhidraLLM/src/main/python
   pip install -r requirements.txt
   ```

3. Generate protobuf stubs:
   ```bash
   python generate_proto.py
   ```

4. Set your Google API key in `start_ghidra_llm.bat`:
   ```batch
   set GOOGLE_API_KEY=your_api_key_here
   ```

## Usage

1. Start Ghidra with LLM integration:
   ```bash
   ./start_ghidra_llm.bat
   ```

2. The LLM panel will appear on the right side of the Ghidra UI.

3. Use the panel to:
   - Ask questions about the current binary
   - Get explanations of code or assembly
   - Request analysis suggestions
   - Get vulnerability assessments

## Features

### Binary Analysis
The LLM can analyze binaries and provide:
- High-level overview of the program
- Identification of key functions and components
- Potential security concerns
- Suggested analysis steps

### Code Explanation
Get detailed explanations of:
- Assembly code
- Decompiled code
- Function behavior
- Security implications

### Analysis Suggestions
Receive AI-powered suggestions for:
- Next analysis steps
- Areas to investigate
- Potential vulnerabilities to check
- Tools and techniques to apply

## Architecture

The integration consists of several components:

1. **Java Plugin (`GhidraLLMPlugin.java`)**
   - Main Ghidra plugin
   - UI components
   - Program analysis integration

2. **gRPC Server (`server.py`)**
   - Python-based gRPC server
   - Handles communication between Ghidra and LLM
   - Manages LLM requests and responses

3. **LLM Client (`client.py`)**
   - Python client for Google's Gemini API
   - Handles LLM interactions
   - Formats requests and responses

4. **Communication Bridge**
   - Protocol Buffers for message definition
   - gRPC for RPC communication
   - Secure and efficient data transfer

## Development

### Building from Source

1. Build the Java components:
   ```bash
   ./gradlew build
   ```

2. Generate protobuf stubs:
   ```bash
   python generate_proto.py
   ```

3. Run tests:
   ```bash
   ./gradlew test
   python -m pytest tests/
   ```

### Adding New Features

1. Define new message types in `ghidra_llm.proto`
2. Generate updated protobuf stubs
3. Implement new methods in the Java and Python components
4. Add UI elements in `LLMPanel.java`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Acknowledgments

- Ghidra team for the excellent reverse engineering framework
- Google for the Gemini LLM API
- The open-source community for various tools and libraries used in this project 