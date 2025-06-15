import os
import subprocess
import sys

def generate_proto_stubs():
    """Generate Python protobuf stubs from the proto definition."""
    proto_dir = os.path.join(os.path.dirname(__file__), '..', 'proto')
    output_dir = os.path.dirname(__file__)
    
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate Python stubs
    proto_file = os.path.join(proto_dir, 'ghidra_llm.proto')
    cmd = [
        'protoc',
        f'--python_out={output_dir}',
        f'--grpc_python_out={output_dir}',
        f'--proto_path={proto_dir}',
        proto_file
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print("Successfully generated Python protobuf stubs")
    except subprocess.CalledProcessError as e:
        print(f"Error generating protobuf stubs: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: protoc not found. Please install the Protocol Buffers compiler.")
        sys.exit(1)

if __name__ == '__main__':
    generate_proto_stubs() 