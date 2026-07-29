-- System messages: revokemsg XML should be extracted to readable text;
-- plain-text system messages should pass through unchanged.

-- Row 1: revokemsg XML (should extract content tag)
INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content, is_group)
VALUES (1, 100001, 10000, '', 'group_test@chatroom', 1700000001,
  '<?xml version="1.0"?><sysmsg type="revokemsg"><revokemsg><content>"测试用户A" 撤回了一条消息</content><revoketime>0</revoketime></revokemsg></sysmsg>',
  1);

-- Row 2: plain-text system message (should pass through as-is)
INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content, is_group)
VALUES (2, 100002, 10000, '', 'group_test@chatroom', 1700000002,
  '你邀请"测试用户B"加入了群聊',
  1);

-- Row 3: revokemsg XML with CDATA content
INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content, is_group)
VALUES (3, 100003, 10000, '', 'wxid_test_private', 1700000003,
  '<?xml version="1.0"?><sysmsg type="revokemsg"><revokemsg><content><![CDATA["测试用户C" 撤回了一条消息]]></content><revoketime>0</revoketime></revokemsg></sysmsg>',
  0);

-- Row 4: group sender prefix + revokemsg XML (group context)
INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content, is_group)
VALUES (4, 100004, 10000, '', 'group_test@chatroom', 1700000004,
  '<?xml version="1.0"?><sysmsg type="revokemsg"><revokemsg><content>"测试用户D" 撤回了一条消息</content><revoketime>1700000000</revoketime></revokemsg></sysmsg>',
  1);
