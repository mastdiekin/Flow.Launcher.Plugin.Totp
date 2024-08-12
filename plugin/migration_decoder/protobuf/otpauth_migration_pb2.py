# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: otpauth-migration.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x17otpauth-migration.proto\x12\x11otpauth_migration\"\xa7\x05\n\x07Payload\x12@\n\x0eotp_parameters\x18\x01 \x03(\x0b\x32(.otpauth_migration.Payload.OtpParameters\x12\x0f\n\x07version\x18\x02 \x01(\x05\x12\x12\n\nbatch_size\x18\x03 \x01(\x05\x12\x13\n\x0b\x62\x61tch_index\x18\x04 \x01(\x05\x12\x10\n\x08\x62\x61tch_id\x18\x05 \x01(\x05\x1a\xf0\x01\n\rOtpParameters\x12\x0e\n\x06secret\x18\x01 \x01(\x0c\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x0e\n\x06issuer\x18\x03 \x01(\t\x12\x37\n\talgorithm\x18\x04 \x01(\x0e\x32$.otpauth_migration.Payload.Algorithm\x12\x35\n\x06\x64igits\x18\x05 \x01(\x0e\x32%.otpauth_migration.Payload.DigitCount\x12\x30\n\x04type\x18\x06 \x01(\x0e\x32\".otpauth_migration.Payload.OtpType\x12\x0f\n\x07\x63ounter\x18\x07 \x01(\x03\"y\n\tAlgorithm\x12\x19\n\x15\x41LGORITHM_UNSPECIFIED\x10\x00\x12\x12\n\x0e\x41LGORITHM_SHA1\x10\x01\x12\x14\n\x10\x41LGORITHM_SHA256\x10\x02\x12\x14\n\x10\x41LGORITHM_SHA512\x10\x03\x12\x11\n\rALGORITHM_MD5\x10\x04\"U\n\nDigitCount\x12\x1b\n\x17\x44IGIT_COUNT_UNSPECIFIED\x10\x00\x12\x13\n\x0f\x44IGIT_COUNT_SIX\x10\x01\x12\x15\n\x11\x44IGIT_COUNT_EIGHT\x10\x02\"I\n\x07OtpType\x12\x18\n\x14OTP_TYPE_UNSPECIFIED\x10\x00\x12\x11\n\rOTP_TYPE_HOTP\x10\x01\x12\x11\n\rOTP_TYPE_TOTP\x10\x02\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'otpauth_migration_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _globals['_PAYLOAD']._serialized_start=47
  _globals['_PAYLOAD']._serialized_end=726
  _globals['_PAYLOAD_OTPPARAMETERS']._serialized_start=201
  _globals['_PAYLOAD_OTPPARAMETERS']._serialized_end=441
  _globals['_PAYLOAD_ALGORITHM']._serialized_start=443
  _globals['_PAYLOAD_ALGORITHM']._serialized_end=564
  _globals['_PAYLOAD_DIGITCOUNT']._serialized_start=566
  _globals['_PAYLOAD_DIGITCOUNT']._serialized_end=651
  _globals['_PAYLOAD_OTPTYPE']._serialized_start=653
  _globals['_PAYLOAD_OTPTYPE']._serialized_end=726
# @@protoc_insertion_point(module_scope)