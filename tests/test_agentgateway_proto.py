from agent_bailiff.adapters.agentgateway._proto import ext_mcp_pb2


def test_generated_stubs_carry_the_ext_mcp_service():
    service = ext_mcp_pb2.DESCRIPTOR.services_by_name["ExtMcp"]
    assert service.full_name == "agentgateway.dev.ext_mcp.ExtMcp"
    methods = {method.name: (method.input_type.name, method.output_type.name) for method in service.methods}
    assert methods == {
        "CheckRequest": ("McpRequest", "McpRequestResult"),
        "CheckResponse": ("McpResponse", "McpResponseResult"),
    }


def test_request_result_offers_pass_error_header_mutation_and_metadata():
    fields = set(ext_mcp_pb2.McpRequestResult.DESCRIPTOR.fields_by_name)
    assert fields == {"pass", "mutated", "error", "header_mutation", "metadata"}
