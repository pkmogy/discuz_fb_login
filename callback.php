<?php

require './source/class/class_core.php';
$discuz = C::app();
$discuz->init();
require libfile('function/member');


//取得FB資訊，建立json
    $user->username=$_GET["id"];
    $user->email=$_GET["email"];
    $user->time=time();
    $user->ip=$_SERVER["REMOTE_ADDR"];
    $myObj->ec = 0;
    $myObj->em = "";
    $myObj->user = $user ;

    $info = json_encode($myObj);

//取json內容
$fbiinfo = json_decode($info, true);

//json錯誤
if (!$fbiinfo || $fbiinfo['ec'] > 0) {
	showmessage($fbiinfo['em']);
}

//取得用戶名，將值给$username
$username = $fbiinfo['user']['username'];
//註冊用的email，獲取email，如果沒有，隨機生成亦可，email需要通過strtolower轉為小寫，否則驗證不通過
$email = strtolower($fbiinfo['user']['email']);
//根據用戶名查詢uid，進而判斷是否為論壇用戶
$uid = C::t('common_member')->fetch_uid_by_username($username);


/*
 * 以下代碼來自source/class/class_member.php
 * 登陸部分來自於on_login函數
 * 註冊部分來自於on_register函數
 * 將$this->setting使用$_G['setting']代替
 */

//判斷uid是否存在，存在即登錄，不存在即註冊
if ($uid) {
	//判斷當前是否已經登陸，已經登錄則不進行跳轉
	if($_G['uid']) {
		$referer = dreferer();
		//如果登陸地址中包含本文件的文件名，即callback.php，則跳轉到首頁，防止刷新造成無限重定向
		if( strpos($referer, 'callback')) {
			$referer = 'forum.php';
		}
		$ucsynlogin = $_G['setting']['allowsynlogin'] ? uc_user_synlogin($_G['uid']) : '';
		$param = array('username' => $_G['member']['username'], 'usergroup' => $_G['group']['grouptitle'], 'uid' => $_G['member']['uid']);
		showmessage('login_succeed', 'forum.php', $param, array('showdialog' => 1, 'locationtime' => true, 'extrajs' => $ucsynlogin));
	}
	
	//初始化uid、用戶名、密碼
	$_G['uid'] = $_G['member']['uid'] = 0;
	$_G['username'] = $_G['member']['username'] = $_G['member']['password'] = '';
	
	//此處$return相關代碼來自於source/function/function_member.php中的userlogin函數，因需要修改簡化，所以沒有調用原函數
	//原userlogin函數begin
	$return = array();
	$return['ucresult'] = array($uid, $fbiinfo['user']['username'], '', $fbiinfo['user']['email'], 0);
	
	$tmp = array();
	$duplicate = '';
	list($tmp['uid'], $tmp['username'], $tmp['password'], $tmp['email'], $duplicate) = $return['ucresult'];
	$return['ucresult'] = $tmp;

	$member = getuserbyuid($return['ucresult']['uid'], 1);
	if(!$member || empty($member['uid'])) {
		showmessage('獲取用戶信息失敗，請聯繫管理員');
	} else {
		$return['member'] = $member;
		$return['status'] = 1;
	}
	if($member['_inarchive']) {
		C::t('common_member_archive')->move_to_master($member['uid']);
	}
	if($member['email'] != $return['ucresult']['email']) {
		C::t('common_member')->update($return['ucresult']['uid'], array('email' => $return['ucresult']['email']));
	}
	//原userlogin函數end

	//將userlogin中返回的$return賦值給$result
	$result = $return;
	$uid = $result['ucresult']['uid'];

	setloginstatus($result['member'], $_GET['cookietime'] ? 2592000 : 0);
	checkfollowfeed();

	if($_G['member']['lastip'] && $_G['member']['lastvisit']) {
		dsetcookie('lip', $_G['member']['lastip'].','.$_G['member']['lastvisit']);
	}
	C::t('common_member_status')->update($_G['uid'], array('lastip' => $_G['clientip'], 'port' => $_G['remoteport'], 'lastvisit' =>TIMESTAMP, 'lastactivity' => TIMESTAMP));
	$ucsynlogin = $_G['setting']['allowsynlogin'] ? uc_user_synlogin($_G['uid']) : '';

	if($_G['member']['adminid'] != 1) {
		if($_G['setting']['accountguard']['loginoutofdate'] && $_G['member']['lastvisit'] && TIMESTAMP - $_G['member']['lastvisit'] > 90 * 86400) {
			C::t('common_member')->update($_G['uid'], array('freeze' => 2));
			C::t('common_member_validate')->insert(array(
				'uid' => $_G['uid'],
				'submitdate' => TIMESTAMP,
				'moddate' => 0,
				'admin' => '',
				'submittimes' => 1,
				'status' => 0,
				'message' => '',
				'remark' => '',
			), false, true);
			manage_addnotify('verifyuser');
			showmessage('location_login_outofdate', 'home.php?mod=spacecp&ac=profile&op=password&resend=1', array('type' => 1), array('showdialog' => true, 'striptags' => false, 'locationtime' => true));
		}

		if($_G['setting']['accountguard']['loginpwcheck'] && $pwold) {
			$freeze = $pwold;
			if($_G['setting']['accountguard']['loginpwcheck'] == 2 && $freeze) {
				C::t('common_member')->update($_G['uid'], array('freeze' => 1));
			}
		}
	}

	$param = array(
		'username' => $result['ucresult']['username'],
		'usergroup' => $_G['group']['grouptitle'],
		'uid' => $_G['member']['uid'],
		'groupid' => $_G['groupid'],
		'syn' => $ucsynlogin ? 1 : 0
	);

	$extra = array(
		'showdialog' => true,
		'locationtime' => true,
		'extrajs' => $ucsynlogin
	);
	if(!$freeze || !$_G['setting']['accountguard']['loginpwcheck']) {
		$loginmessage = $_G['groupid'] == 8 ? 'login_succeed_inactive_member' : 'login_succeed';
		$location = $invite || $_G['groupid'] == 8 ? 'home.php?mod=space&do=home' : dreferer();
	} else {
		$loginmessage = 'login_succeed_password_change';
		$location = 'home.php?mod=spacecp&ac=profile&op=password';
		$_GET['lssubmit'] = 0;
	}
	showmessage($loginmessage, 'forum.php', $param, $extra);//修改過
} else {
	//註冊，如果已經登錄，則不進行註冊
	if($_G['uid']) {
		$ucsynlogin = $_G['setting']['allowsynlogin'] ? uc_user_synlogin($_G['uid']) : '';
		$url_forward = dreferer();
		if(strpos($url_forward, $_G['setting']['regname']) !== false) {
			$url_forward = 'forum.php';
		}
		if(strpos($url_forward, 'callback')) {
			$url_forward = 'forum.php';
		}
		showmessage('login_succeed', $url_forward ? $url_forward : './', array('username' => $_G['member']['username'], 'usergroup' => $_G['group']['grouptitle'], 'uid' => $_G['uid']), array('extrajs' => $ucsynlogin));
	} elseif(!$_G['setting']['regclosed'] && (!$_G['setting']['regstatus'] || !$_G['setting']['ucactivation'])) {
		if($_GET['action'] == 'activation' || $_GET['activationauth']) {
			if(!$_G['setting']['ucactivation'] && !$_G['setting']['closedallowactivation']) {
				showmessage('register_disable_activation');
			}
		} elseif(!$_G['setting']['regstatus']) {
			if($_G['setting']['regconnect']) {
				dheader('location:connect.php?mod=login&op=init&referer=forum.php&statfrom=login_simple');
			}
			showmessage(!$_G['setting']['regclosemessage'] ? 'register_disable' : str_replace(array("\r", "\n"), '', $_G['setting']['regclosemessage']));
		}
	}
	
	require_once libfile('function/misc');
	require_once libfile('function/profile');
	if(!function_exists('sendmail')) {
		include libfile('function/mail');
	}
	loaducenter();
	
	$welcomemsg = & $_G['setting']['welcomemsg'];
	$welcomemsgtitle = & $_G['setting']['welcomemsgtitle'];
	$welcomemsgtxt = & $_G['setting']['welcomemsgtxt'];

	
	//檢查新註冊用戶驗證方式
	if($_G['setting']['regverify']) {
		if($_G['setting']['areaverifywhite']) {
			$location = $whitearea = '';
			$location = trim(convertip($_G['clientip'], "./"));
			if($location) {
				$whitearea = preg_quote(trim($_G['setting']['areaverifywhite']), '/');
				$whitearea = str_replace(array("\\*"), array('.*'), $whitearea);
				$whitearea = '.*'.$whitearea.'.*';
				$whitearea = '/^('.str_replace(array("\r\n", ' '), array('.*|.*', ''), $whitearea).')$/i';
				if(@preg_match($whitearea, $location)) {
					$_G['setting']['regverify'] = 0;
				}
			}
		}

		if($_G['cache']['ipctrl']['ipverifywhite']) {
			foreach(explode("\n", $_G['cache']['ipctrl']['ipverifywhite']) as $ctrlip) {
				if(preg_match("/^(".preg_quote(($ctrlip = trim($ctrlip)), '/').")/", $_G['clientip'])) {
					$_G['setting']['regverify'] = 0;
					break;
				}
			}
		}
	}
	
	//註冊驗證分配用戶組，8是等待驗證用戶組
	$groupinfo = array();
	if($_G['setting']['regverify']) {
		$groupinfo['groupid'] = 8;
	} else {
		$groupinfo['groupid'] = $_G['setting']['newusergroupid'];
	}
		
	//註冊控制
	if($_G['setting']['regctrl']) {
		if(C::t('common_regip')->count_by_ip_dateline($ctrlip, $_G['timestamp']-$_G['setting']['regctrl']*3600)) {
			showmessage('register_ctrl', NULL, array('regctrl' => $_G['setting']['regctrl']));
		}
	}
	
	$setregip = null;
	if($_G['setting']['regfloodctrl']) {
		$regip = C::t('common_regip')->fetch_by_ip_dateline($_G['clientip'], $_G['timestamp']-86400);
		if($regip) {
			if($regip['count'] >= $_G['setting']['regfloodctrl']) {
				showmessage('register_flood_ctrl', NULL, array('regfloodctrl' => $_G['setting']['regfloodctrl']));
			} else {
				$setregip = 1;
			}
		} else {
			$setregip = 2;
		}
	}
	

	//進行註冊
	$uid = uc_user_register(addslashes($username), $password, $email, $questionid, $answer, $_G['clientip']);
	if($uid <= 0) {
		if($uid == -1) {
			showmessage('profile_username_illegal');
		} elseif($uid == -2) {
			showmessage('profile_username_protect');
		} elseif($uid == -3) {
			showmessage('profile_username_duplicate');
		} elseif($uid == -4) {
			showmessage('profile_email_illegal');
		} elseif($uid == -5) {
			showmessage('profile_email_domain_illegal');
		} elseif($uid == -6) {
			showmessage('profile_email_duplicate');
		} else {
			showmessage('undefined_action');
		}
	}
	
	$_G['username'] = $username;
	if(getuserbyuid($uid, 1)) {
		if(!$activation) {
			uc_user_delete($uid);
		}
		showmessage('profile_uid_duplicate', '', array('uid' => $uid));
	}
	
	$password = md5(random(10));
	$secques = $questionid > 0 ? random(8) : '';
	
	if($setregip !== null) {
		if($setregip == 1) {
			C::t('common_regip')->update_count_by_ip($_G['clientip']);
		} else {
			C::t('common_regip')->insert(array('ip' => $_G['clientip'], 'count' => 1, 'dateline' => $_G['timestamp']));
		}
	}
	
	
	$init_arr = array('credits' => explode(',', $_G['setting']['initcredits']), 'profile'=>$profile, 'emailstatus' => $emailstatus);

	C::t('common_member')->insert($uid, $username, $password, $email, $_G['clientip'], $groupinfo['groupid'], $init_arr);

	require_once libfile('cache/userstats', 'function');
	build_cache_userstats();
	
	if($_G['setting']['regctrl'] || $_G['setting']['regfloodctrl']) {
		C::t('common_regip')->delete_by_dateline($_G['timestamp']-($_G['setting']['regctrl'] > 72 ? $_G['setting']['regctrl'] : 72)*3600);
		if($_G['setting']['regctrl']) {
			C::t('common_regip')->insert(array('ip' => $_G['clientip'], 'count' => -1, 'dateline' => $_G['timestamp']));
		}
	}

	$regmessage = dhtmlspecialchars($_GET['regmessage']);
	if($_G['setting']['regverify'] == 2) {
		C::t('common_member_validate')->insert(array(
			'uid' => $uid,
			'submitdate' => $_G['timestamp'],
			'moddate' => 0,
			'admin' => '',
			'submittimes' => 1,
			'status' => 0,
			'message' => $regmessage,
			'remark' => '',
		), false, true);
		manage_addnotify('verifyuser');
	}

	setloginstatus(array(
		'uid' => $uid,
		'username' => $_G['username'],
		'password' => $password,
		'groupid' => $groupinfo['groupid'],
	), 0);
	include_once libfile('function/stat');
	updatestat('register');

	if($welcomemsg && !empty($welcomemsgtxt)) {
		$welcomemsgtitle = replacesitevar($welcomemsgtitle);
		$welcomemsgtxt = replacesitevar($welcomemsgtxt);
		if($welcomemsg == 1) {
			$welcomemsgtxt = nl2br(str_replace(':', '&#58;', $welcomemsgtxt));
			notification_add($uid, 'system', $welcomemsgtxt, array('from_id' => 0, 'from_idtype' => 'welcomemsg'), 1);
		} elseif($welcomemsg == 2) {
			sendmail_cron($email, $welcomemsgtitle, $welcomemsgtxt);
		} elseif($welcomemsg == 3) {
			sendmail_cron($email, $welcomemsgtitle, $welcomemsgtxt);
			$welcomemsgtxt = nl2br(str_replace(':', '&#58;', $welcomemsgtxt));
			notification_add($uid, 'system', $welcomemsgtxt, array('from_id' => 0, 'from_idtype' => 'welcomemsg'), 1);
		}
	}
	
	//註冊推廣
	if($fromuid) {
		updatecreditbyaction('promotion_register', $fromuid);
		dsetcookie('promotion', '');
	}
	dsetcookie('loginuser', '');
	dsetcookie('activationauth', '');
	dsetcookie('invite_auth', '');

	$url_forward = dreferer();
	$refreshtime = 3000;
	switch($_G['setting']['regverify']) {
		case 1:
			$idstring = random(6);
			$authstr = $_G['setting']['regverify'] == 1 ? "$_G[timestamp]\t2\t$idstring" : '';
			C::t('common_member_field_forum')->update($_G['uid'], array('authstr' => $authstr));
			$verifyurl = "{$_G[siteurl]}member.php?mod=activate&amp;uid={$_G[uid]}&amp;id=$idstring";
			$email_verify_message = lang('email', 'email_verify_message', array(
				'username' => $_G['member']['username'],
				'bbname' => $_G['setting']['bbname'],
				'siteurl' => $_G['siteurl'],
				'url' => $verifyurl
			));
			if(!sendmail("$username <$email>", lang('email', 'email_verify_subject'), $email_verify_message)) {
				runlog('sendmail', "$email sendmail failed.");
			}
			$message = 'register_email_verify';
			$locationmessage = 'register_email_verify_location';
			$refreshtime = 10000;
			break;
		case 2:
			$message = 'register_manual_verify';
			$locationmessage = 'register_manual_verify_location';
			break;
		default:
			$message = 'register_succeed';
			$locationmessage = 'register_succeed_location';
			break;
	}
	$param = array('bbname' => $_G['setting']['bbname'], 'username' => $_G['username'], 'usergroup' => $_G['group']['grouptitle'], 'uid' => $_G['uid']);
	if(strpos($url_forward, $_G['setting']['regname']) !== false || strpos($url_forward, 'buyinvitecode') !== false) {
		$url_forward = 'forum.php';
	}
	showmessage($message, $url_forward, $param);
}