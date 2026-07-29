-- Fixture 02: XML null sentinel filtering
-- Tests that <title>null</title> and <des>null</des> are filtered to None.
-- local_type = (5 << 32) | 49 = 21474836529

INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content)
VALUES (
    200,
    900002,
    21474836529,
    'wxid_test_alice',
    'wxid_test_bob',
    1700000200,
    '<msg><appmsg><title>null</title><des>null</des><url>https://example.com/test-link</url><type>5</type></appmsg></msg>'
);
