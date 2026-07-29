-- Fixture 01: u64 local_type (sub_type=57, msg_type=49)
-- Tests that local_type values exceeding 32 bits are correctly split.
-- local_type = (57 << 32) | 49 = 244813135921

INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content)
VALUES (
    100,
    900001,
    244813135921,
    'wxid_test_alice',
    'wxid_test_bob',
    1700000100,
    '<msg><appmsg><title>This is my reply</title><refermsg><fromusr>wxid_test_bob</fromusr><displayname>Bob</displayname><content>Hello, how are you?</content><type>1</type></refermsg></appmsg></msg>'
);
