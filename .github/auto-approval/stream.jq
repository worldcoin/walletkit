if .type == "message_update" and .assistantMessageEvent.type == "text_delta" then
  .assistantMessageEvent.delta
elif .type == "tool_execution_start" then
  "\n[tool started: \(.toolName)]\n"
elif .type == "tool_execution_end" then
  "\n[tool finished: \(.toolName); error=\(.isError)]\n"
elif .type == "message_end" and .message.role == "assistant" then
  "\n[assistant finished: \(.message.stopReason)]\n"
else
  empty
end
