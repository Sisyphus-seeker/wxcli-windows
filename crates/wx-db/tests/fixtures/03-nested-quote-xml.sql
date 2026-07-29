-- Fixture 03: Nested quote XML
-- Tests that when <content> inside <refermsg> contains nested <msg><appmsg>,
-- the title is extracted from the inner XML rather than showing raw XML.
-- local_type = (57 << 32) | 49 = 244813135921

INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content)
VALUES (
    300,
    900003,
    244813135921,
    'wxid_test_alice',
    'wxid_test_bob',
    1700000300,
    '<msg><appmsg><title>I agree with this</title><refermsg><fromusr>wxid_test_bob</fromusr><displayname>Bob</displayname><type>49</type><content><msg><appmsg><title>Shared article about testing</title><des>A comprehensive guide</des></appmsg></msg></content></refermsg></appmsg></msg>'
);
