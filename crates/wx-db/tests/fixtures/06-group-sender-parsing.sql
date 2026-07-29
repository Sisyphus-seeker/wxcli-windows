-- Fixture 06: Group sender parsing
-- Tests group sender prefix extraction from message content.
-- is_group=1, talker is a chatroom, message_content has "wxid:\n" prefix.
-- sender column is set to wxid_test_alice to verify it gets overridden
-- by the content prefix (wxid_test_bob).

INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content, is_group)
VALUES (
    600,
    900006,
    1,
    'wxid_test_alice',
    'group_test@chatroom',
    1700000600,
    'wxid_test_bob:' || char(10) || 'Hello from the group chat',
    1
);
