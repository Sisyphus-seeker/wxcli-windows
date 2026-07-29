-- Fixture 07: Group chat quote with <chatusr> tag
-- In group chats, <refermsg><fromusr> contains the chatroom ID (not the sender),
-- while <chatusr> contains the actual quoted sender's wxid.
-- This fixture reproduces the real XML structure for BUG-2 verification.
-- local_type = (57 << 32) | 49 = 244813135921
-- is_group = 1 (group chat, sender prefix in content)

INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content, is_group)
VALUES (
    700,
    900007,
    244813135921,
    '',
    'group_test@chatroom',
    1700000700,
    'wxid_test_quoter:
<?xml version="1.0"?>
<msg>
	<appmsg appid="" sdkver="0">
		<title>同意这个观点</title>
		<type>57</type>
		<appattach>
			<cdnthumbaeskey />
			<aeskey></aeskey>
		</appattach>
		<refermsg>
			<type>1</type>
			<svrid>2041776388084106207</svrid>
			<fromusr>group_test@chatroom</fromusr>
			<chatusr>wxid_test_hidden</chatusr>
			<displayname>隐藏用户</displayname>
			<content>这是被引用的原始消息</content>
			<msgsource>&lt;msgsource&gt;&lt;sequence_id&gt;854104363&lt;/sequence_id&gt;&lt;/msgsource&gt;</msgsource>
			<createtime>1700000600</createtime>
		</refermsg>
	</appmsg>
	<fromusername>wxid_test_quoter</fromusername>
	<scene>0</scene>
	<appinfo>
		<version>1</version>
		<appname />
	</appinfo>
	<commenturl />
</msg>',
    1
);

-- Also include a private chat quote for comparison (fromusr is the actual sender)
INSERT INTO fixture_messages (sort_seq, server_id, local_type, sender, talker, create_time, message_content, is_group)
VALUES (
    701,
    900008,
    244813135921,
    'wxid_test_alice',
    'wxid_test_bob',
    1700000701,
    '<msg><appmsg><title>好的收到</title><type>57</type><refermsg><fromusr>wxid_test_bob</fromusr><displayname>Bob</displayname><type>1</type><content>明天见面吧</content></refermsg></appmsg></msg>',
    0
);
