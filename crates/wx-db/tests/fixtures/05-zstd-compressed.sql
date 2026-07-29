-- Fixture 05: zstd-compressed message content
-- Tests the zstd decode path when wcdb_ct=4 and message_content is a zstd blob.
-- local_type = (5 << 32) | 49 = 21474836529
-- The blob is zstd-compressed XML:
--   <msg><appmsg><title>Test Article Link</title><des>This is a test article description for snapshot testing</des><url>https://example.com/test-article</url><type>5</type></appmsg></msg>

INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content, wcdb_ct)
VALUES (
    500,
    900005,
    21474836529,
    'wxid_test_alice',
    'wxid_test_bob',
    1700000500,
    X'28b52ffd045825040092c81a1b80356d034158e9946ec229cdfe6a05625208b283f83689948b0d18813c8eeef09090ca018d7956722838a4cc400fa302a0778573379267259857e3f048db0a3997745b0a61496df32e73358af5b5add8d7be489157030f13690fa6c76c2f83f5b5483dbdcd5c308f230c08002743d8ead627a410b047526d5ccadd78225e5be419f2b045',
    4
);
