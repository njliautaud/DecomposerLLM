@echo off
setlocal

REM =============================================
REM EDIT THESE VALUES WITH YOUR ACTUAL SETTINGS
REM =============================================

REM Your Google Gemini API key
set GOOGLE_API_KEY=AIzaSyBCH5UaffU1gPRJdWpp0UV6B5xcuVpc7KQ

REM Your Ghidra installation path - UPDATE THIS TO YOUR ACTUAL GHIDRA PATH
set GHIDRA_HOME=C:\Program Files\ghidra_10.3.3

REM =============================================
REM DO NOT EDIT BELOW THIS LINE
REM =============================================

REM Set Python path
set PYTHONPATH=src/main/python

echo Setting up environment...

REM Install required Python packages
echo Installing Python dependencies...
pip install -r src\main\python\requirements.txt
pip install -r src\main\python\requirements-test.txt
pip install grpcio-tools

REM Create proto directory if it doesn't exist
if not exist "src\main\proto" mkdir "src\main\proto"

REM Generate Python protobuf stubs
echo Generating protobuf stubs...
python -m grpc_tools.protoc -I./src/main/proto --python_out=./src/main/python --grpc_python_out=./src/main/python ./src/main/proto/ghidra_llm.proto

REM Create a temporary .env file for Python
echo GOOGLE_API_KEY=%GOOGLE_API_KEY% > src\main\python\.env

echo Starting Python gRPC server...
cd src\main\python
start /B python -m ghidra_llm.server
cd ..\..\..

echo Waiting for server to initialize...
timeout /t 5 /nobreak

echo Starting Ghidra with LLM integration...
if exist "%GHIDRA_HOME%\ghidraRun.bat" (
    "%GHIDRA_HOME%\ghidraRun.bat" ^
        --add-modules GhidraLLM,Debugger,Debugger-api,Debugger-rmi-trace ^
        --add-opens java.base/java.lang=ALL-UNNAMED ^
        --add-opens java.base/java.util=ALL-UNNAMED ^
        --add-opens java.base/java.io=ALL-UNNAMED
) else (
    echo Error: Ghidra not found at %GHIDRA_HOME%
    echo Please update the GHIDRA_HOME path in start.bat to point to your Ghidra installation
    pause
)

endlocal 