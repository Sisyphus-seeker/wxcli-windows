-- Fixture 04: Empty title with channel video
-- Tests title→des fallback for channel video messages.
-- local_type = (51 << 32) | 49 = 219043332145

INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content)
VALUES (
    400,
    900004,
    219043332145,
    'wxid_test_alice',
    'wxid_test_bob',
    1700000400,
    '<msg><appmsg><title></title><des>This is a channel video description</des><type>51</type></appmsg></msg>'
);
