# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: ghidra_llm.proto
# Protobuf Python Version: 6.31.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    6,
    31,
    0,
    '',
    'ghidra_llm.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10ghidra_llm.proto\x12\nghidra.llm\"\x99\x01\n\x0cQueryRequest\x12\r\n\x05query\x18\x01 \x01(\t\x12\x0f\n\x07\x63ontext\x18\x02 \x01(\t\x12\x38\n\x08metadata\x18\x03 \x03(\x0b\x32&.ghidra.llm.QueryRequest.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"!\n\rQueryResponse\x12\x10\n\x08response\x18\x01 \x01(\t\"\xc8\x01\n\x15\x42inaryAnalysisRequest\x12\x13\n\x0b\x62inary_path\x18\x01 \x01(\t\x12\x14\n\x0c\x61rchitecture\x18\x02 \x01(\t\x12\x13\n\x0b\x65ntry_point\x18\x03 \x01(\x04\x12%\n\x08sections\x18\x04 \x03(\x0b\x32\x13.ghidra.llm.Section\x12#\n\x07imports\x18\x05 \x03(\x0b\x32\x12.ghidra.llm.Import\x12#\n\x07\x65xports\x18\x06 \x03(\x0b\x32\x12.ghidra.llm.Export\"*\n\x16\x42inaryAnalysisResponse\x12\x10\n\x08\x61nalysis\x18\x01 \x01(\t\"I\n\x16\x43odeExplanationRequest\x12\x0c\n\x04\x63ode\x18\x01 \x01(\t\x12\x10\n\x08language\x18\x02 \x01(\t\x12\x0f\n\x07\x63ontext\x18\x03 \x01(\t\".\n\x17\x43odeExplanationResponse\x12\x13\n\x0b\x65xplanation\x18\x01 \x01(\t\"\xc6\x01\n\x19\x41nalysisSuggestionRequest\x12\x18\n\x10\x63urrent_analysis\x18\x01 \x01(\t\x12\x17\n\x0f\x63ompleted_steps\x18\x02 \x03(\t\x12\x45\n\x08\x66indings\x18\x03 \x03(\x0b\x32\x33.ghidra.llm.AnalysisSuggestionRequest.FindingsEntry\x1a/\n\rFindingsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"5\n\x1a\x41nalysisSuggestionResponse\x12\x17\n\x0fsuggested_steps\x18\x01 \x03(\t\"X\n\x07Section\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x15\n\rstart_address\x18\x02 \x01(\x04\x12\x13\n\x0b\x65nd_address\x18\x03 \x01(\x04\x12\x13\n\x0bpermissions\x18\x04 \x01(\t\"8\n\x06Import\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0f\n\x07library\x18\x02 \x01(\t\x12\x0f\n\x07\x61\x64\x64ress\x18\x03 \x01(\x04\"5\n\x06\x45xport\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0f\n\x07\x61\x64\x64ress\x18\x02 \x01(\x04\x12\x0c\n\x04type\x18\x03 \x01(\t2\xe6\x02\n\tGhidraLLM\x12\x41\n\x08QueryLLM\x12\x18.ghidra.llm.QueryRequest\x1a\x19.ghidra.llm.QueryResponse\"\x00\x12X\n\rAnalyzeBinary\x12!.ghidra.llm.BinaryAnalysisRequest\x1a\".ghidra.llm.BinaryAnalysisResponse\"\x00\x12X\n\x0b\x45xplainCode\x12\".ghidra.llm.CodeExplanationRequest\x1a#.ghidra.llm.CodeExplanationResponse\"\x00\x12\x62\n\x0fSuggestAnalysis\x12%.ghidra.llm.AnalysisSuggestionRequest\x1a&.ghidra.llm.AnalysisSuggestionResponse\"\x00\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'ghidra_llm_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_QUERYREQUEST_METADATAENTRY']._loaded_options = None
  _globals['_QUERYREQUEST_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ANALYSISSUGGESTIONREQUEST_FINDINGSENTRY']._loaded_options = None
  _globals['_ANALYSISSUGGESTIONREQUEST_FINDINGSENTRY']._serialized_options = b'8\001'
  _globals['_QUERYREQUEST']._serialized_start=33
  _globals['_QUERYREQUEST']._serialized_end=186
  _globals['_QUERYREQUEST_METADATAENTRY']._serialized_start=139
  _globals['_QUERYREQUEST_METADATAENTRY']._serialized_end=186
  _globals['_QUERYRESPONSE']._serialized_start=188
  _globals['_QUERYRESPONSE']._serialized_end=221
  _globals['_BINARYANALYSISREQUEST']._serialized_start=224
  _globals['_BINARYANALYSISREQUEST']._serialized_end=424
  _globals['_BINARYANALYSISRESPONSE']._serialized_start=426
  _globals['_BINARYANALYSISRESPONSE']._serialized_end=468
  _globals['_CODEEXPLANATIONREQUEST']._serialized_start=470
  _globals['_CODEEXPLANATIONREQUEST']._serialized_end=543
  _globals['_CODEEXPLANATIONRESPONSE']._serialized_start=545
  _globals['_CODEEXPLANATIONRESPONSE']._serialized_end=591
  _globals['_ANALYSISSUGGESTIONREQUEST']._serialized_start=594
  _globals['_ANALYSISSUGGESTIONREQUEST']._serialized_end=792
  _globals['_ANALYSISSUGGESTIONREQUEST_FINDINGSENTRY']._serialized_start=745
  _globals['_ANALYSISSUGGESTIONREQUEST_FINDINGSENTRY']._serialized_end=792
  _globals['_ANALYSISSUGGESTIONRESPONSE']._serialized_start=794
  _globals['_ANALYSISSUGGESTIONRESPONSE']._serialized_end=847
  _globals['_SECTION']._serialized_start=849
  _globals['_SECTION']._serialized_end=937
  _globals['_IMPORT']._serialized_start=939
  _globals['_IMPORT']._serialized_end=995
  _globals['_EXPORT']._serialized_start=997
  _globals['_EXPORT']._serialized_end=1050
  _globals['_GHIDRALLM']._serialized_start=1053
  _globals['_GHIDRALLM']._serialized_end=1411
# @@protoc_insertion_point(module_scope)
