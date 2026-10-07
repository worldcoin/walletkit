reduce inputs as $event ("";
  if $event.type == "message_end" and $event.message.role == "assistant" then
    if $event.message.stopReason == "stop" then
      [$event.message.content[] | select(.type == "text") | .text] | join("\n")
    else
      ""
    end
  else
    .
  end
)
