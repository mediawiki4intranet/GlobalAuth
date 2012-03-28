<?php

/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * @author Vitaliy Filippov <vitalif@mail.ru>
 * @license http://www.gnu.org/copyleft/gpl.html GNU General Public License 2.0 or later
 */

if (!defined('MEDIAWIKI')) die();

require_once(dirname(__FILE__).'/urandom.php');

$wgHooks['MediaWikiPerformAction'][] = 'MWGlobalAuthClient::MediaWikiPerformAction';
$wgHooks['BeforeInitialize'][] = 'MWGlobalAuthClient::MediaWikiBeforeInitialize';

/*  Расширение - клиент глобальной авторизации (GlobalAuth.php - сервер глобальной авторизации)
    Конфигурация:
    $egGlobalAuthServer = '';               // обязательная настройка, URL скрипта сервера авторизации
    $egGlobalAuthClientRequire = false;     // требовать успешной авторизации?
    $egGlobalAuthClientRequireGroup = NULL; // требовать членства пользователя во внешней группе такой-то
                                            // и показывать ошибку $egGlobalAuthGroupAccessDeniedTemplate, если не
    $egGlobalAuthMapToHaloACL = false;      // синхронизировать внешние группы с HaloACL-группами
*/

/* шаблон HTML-сообщения об ошибке доступа по внешней группе */
$egGlobalAuthGroupAccessDeniedTemplate = '
<html>
<head>
<title>403 Forbidden</title>
</head>
<body>
<h1>Forbidden</h1>
Access to this site is only allowed to users who are members of <b>$group</b> <a href="$d[auth_site]" target="_blank">$d[auth_source]</a> group.<br />
Relogin to <a href="$d[auth_site]">$d[auth_source]</a> with appropriate user first, and then <a href="$relogin_url">click here</a>.
<h1>Доступ запрещён</h1>
Доступ к данному сайту разрешён только членам <a href="$d[auth_site]">$d[auth_source]</a>-группы <b>$group</b>.<br />
Сначала перезайдите в <a href="$d[auth_site]" target="_blank">$d[auth_source]</a> под подходящим именем пользователя, а потом <a href="$relogin_url">нажмите сюда</a>.
</body>
</html>
';

class MWGlobalAuthClient
{
    /* Флаг, чтобы не делать повторную проверку */
    static $checked = false;

    /* Спецстраницы, всегда доступные без авторизации */
    static $Whitelist = array(
        'userlogin'     => 1,
        'userlogout'    => 1,
        'confirmemail'  => 1,
    );

    static function MediaWikiBeforeInitialize($title, $article, $output, $user, $request, $mediaWiki)
    {
        return self::handle_and_check();
    }

    static function MediaWikiPerformAction($output, $article, $title, $user, $request, $wiki)
    {
        return self::handle_and_check();
    }

    /* Текущий URL минус параметры запроса глобальной авторизации плюс $append, если он не пуст */
    static function clean_uri($append = array())
    {
        global $wgServer, $wgTitle;
        $gp = $_GET+$_POST;
        foreach(explode(' ', 'id key client res nologin data require') as $k)
            unset($gp["ga_$k"]);
        unset($gp['title']);
        $uri = $wgTitle->getFullUrl($gp+$append);
        return $uri;
    }

    /* Обновить HaloACL-группы с суффиксом $suffix, добавив/удалив откуда надо/куда надо пользователя $user */
    static function map_to_haloacl_groups($user, $groups, $suffix)
    {
        global $wgUser;
        $dbr = wfGetDB(DB_SLAVE);
        /* получаем список внешних групп, в которых уже есть $user */
        $res = $dbr->select(array('halo_acl_group_members', 'halo_acl_groups'), 'group_name',
            array(
                'group_name LIKE '.$dbr->addQuotes('Group/%'.$suffix),
                'group_id=parent_group_id',
                'child_type' => 'user',
                'child_id' => $user->getId()
            ),
            __METHOD__
        );
        /* вычисляем разницу между теми, что есть и теми, что надо */
        $add_groups = array();
        foreach ($groups as $g)
        {
            $g = str_replace('_', ' ', trim($g, " _").$suffix);
            $g = mb_strtoupper(mb_substr($g, 0, 1)) . mb_substr($g, 1);
            $add_groups["Group/$g"] = 1;
        }
        $remove_groups = array();
        while ($row = $dbr->fetchRow($res))
        {
            $g = $row[0];
            $g = str_replace('_', ' ', $g);
            if (!array_key_exists($g, $add_groups))
                $remove_groups[] = $g;
            unset($add_groups[$g]);
        }
        $dbr->freeResult($res);
        $remove_groups = array_flip($remove_groups);
        if (!$add_groups && !$remove_groups)
            return;
        /* получаем составы всех редактируемых групп */
        $res = $dbr->select(
            array('halo_acl_group_members', 'halo_acl_groups', 'user'), 'group_name, user_name',
            array(
                'group_name' => array_keys($add_groups+$remove_groups),
                'group_id=parent_group_id',
                'child_type' => 'user',
                'child_id=user_id'
            ),
            __METHOD__
        );
        $members = array();
        while ($row = $dbr->fetchRow($res))
            $members[$row[0]][$row[1]] = true;
        $dbr->freeResult($res);
        /* добавляем / удаляем пользователя в группы */
        foreach ($add_groups as $a => $true)
            $members[$a][$user->getName()] = true;
        foreach ($remove_groups as $r => $true)
            unset($members[$r][$user->getName()]);
        /* обновляем группы из-под имени WikiSysop'а */
        $old_user = $wgUser;
        ### CustIS Bug 72303
        global $wgRequest;
        $old_title = $_REQUEST['title'];
        unset($_POST['title']);
        unset($_REQUEST['title']);
        unset($_GET['title']);
        $wgRequest->setVal('title', '');
        $wgUser = User::newFromName('WikiSysop');
        foreach ($members as $group => $users)
        {
            $grptitle = Title::newFromText("ACL:$group");
            if (!$grptitle)
                continue;
            $content = array();
            foreach ($users as $u => $true)
                $content[] = 'User:'.$u;
            $content =
                "{{#member:members=".implode(',',$content)."}}\n" .
                "{{#manage group:assigned to=User:WikiSysop}}\n" .
                "[[Category:ACL/Group]]";
            $article = new Article($grptitle);
            if ($article->getTitle()->getText() != $group)
                die("Щас перезапишу неправильную страницу: '".$article->getTitle()->getText()."'!!! // Синхронизатор групп");
            $article->doEdit($content, "Update ACL:$group", EDIT_FORCE_BOT);
        }
        $wgUser = $old_user;
        ### CustIS Bug 72303
        if ($old_title)
        {
            $wgRequest->setVal('title', $old_title);
            $_GET['title'] = $_REQUEST['title'] = $old_title;
        }
    }

    // Обработать команды авторизации и проверить доступ
    static function handle_and_check()
    {
        global $wgUser, $wgRequest, $wgTitle, $wgCookiePrefix;
        global $egGlobalAuthClientRequire, $egGlobalAuthClientRequireGroup, $egGlobalAuthServer, $egGlobalAuthMapToHaloACL;
        if (!$egGlobalAuthServer || self::$checked)
            return true;
        $v = $wgRequest->getValues();
        if (isset($v['ga_client']) && isset($v['ga_id']))
        {
            $id = $v['ga_id'];
            $cache = wfGetCache(CACHE_DB);
            $cachekey = wfMemcKey('ga-ckey', $id);
            $datakey = wfMemcKey('ga-cdata', $id);
            $secret = $cache->get($cachekey);
            // сервер передаёт нам данные, их надо сохранить в кэше
            if (!empty($v['ga_key']))
            {
                if ($v['ga_key'] == $secret)
                {
                    $cache->delete($cachekey);
                    if ($v['ga_nologin'])
                        $data = 'nologin';
                    elseif ($v['ga_data'])
                        $data = (array)json_decode(utf8_decode($v['ga_data']));
                    if ($data)
                    {
                        $cache->set($datakey, $data, 86400);
                        print "1";
                        exit;
                    }
                }
                wfGetDB(DB_MASTER)->commit();
                header("HTTP/1.1 404 Not Found");
                exit;
            }
            // к нам пришёл пользователь, его надо авторизовать или послать
            else
            {
                if ($d = $cache->get($datakey))
                {
                    $user = self::get_user($d);
                    if ($user && !$wgUser->isAnon() && $wgUser->getId() != $user->getId())
                        $user = NULL;
                    if ($egGlobalAuthClientRequireGroup && !in_array($egGlobalAuthClientRequireGroup, $d['user_groups']))
                        self::group_access_denied($d, $egGlobalAuthClientRequireGroup);
                    elseif ($user)
                    {
                        if ($egGlobalAuthMapToHaloACL && class_exists('HACLSecurityDescriptor'))
                        {
                            // нужно отобразить внешние группы на IntraACL-группы
                            // но только если это найденный нами, а не произвольный залогиненный, пользователь
                            self::map_to_haloacl_groups($user, $d['user_groups'], $d['auth_source'] ? ' ('.$d['auth_source'].')' : ' (X)');
                        }
                        $cache->delete($datakey);
                        $cache->set(wfMemcKey('ga-udata', $user->getId()), $d, 86400);
                        if(session_id() == '')
                            wfSetupSession();
                        $user->setCookies();
                    }
                    else
                        $wgRequest->response()->setcookie('globalauth', $id);
                }
                else
                    $wgRequest->response()->setcookie('globalauth', $id);
                wfGetDB(DB_MASTER)->commit();
                header("Location: ".self::clean_uri());
                exit;
            }
        }
        if ((!$wgTitle || $wgTitle->getNamespace() != NS_SPECIAL || !self::$Whitelist[strtolower($wgTitle->getText())]) &&
            (!empty($_REQUEST['ga_require']) || empty($_COOKIE[$wgCookiePrefix.'LoggedOut']) ||
            wfTimestamp(TS_UNIX, $_COOKIE[$wgCookiePrefix.'LoggedOut'])+300 < time()))
        {
            wfDebug(__CLASS__.": checking global auth\n");
            self::require_auth($egGlobalAuthClientRequire, !empty($_REQUEST['ga_require']));
        }
        self::$checked = true;
        return true;
    }

    /* получить локального пользователя по внешним данным $d */
    static function get_user($d)
    {
        $emails = array($d['user_email'] => 1);
        if (is_array($d['user_email_aliases']))
            $emails += array_flip($d['user_email_aliases']);
        $dbr = wfGetDB(DB_SLAVE);
        foreach (array_keys($emails) as $email)
            if ($userid = $dbr->selectField('user', 'user_id', array('user_email' => $email, 'user_email_authenticated IS NOT NULL'), __METHOD__))
                return User::newFromId($userid);
        return NULL;
    }

    /* показать страницу с ошибкой доступа по группе $group */
    static function group_access_denied($d, $group)
    {
        global $egGlobalAuthGroupAccessDeniedTemplate;
        $relogin_url = self::clean_uri(array('ga_require' => 1));
        header("HTTP/1.1 403 Forbidden");
        header("Content-Type: text/html; charset=utf-8");
        print eval('return "'.str_replace(array("\\",'"'),array("\\\\",'\\"'),$egGlobalAuthGroupAccessDeniedTemplate).'";');
        exit;
    }

    /* Left in for debugging */
    static function vdump($v)
    {
        ob_start();
        var_dump($v);
        $r = ob_get_contents();
        ob_end_flush();
        return trim($r);
    }

    /* инициировать глобальную авторизацию,
       требовать успешную авторизацию при $require,
       инициировать глобальную авторизацию заново при $force */
    static function require_auth($require = false, $force = false)
    {
        global $wgUser, $wgRequest, $wgCookiePrefix;
        global $egGlobalAuthClientRequireGroup, $egGlobalAuthServer, $egGlobalAuthWhitelistUsers;
        if (!$egGlobalAuthServer)
            return;
        $cache = wfGetCache(CACHE_DB);
        $require = $require || $force;
        $rg = $egGlobalAuthClientRequireGroup;
        /* в каких случаях нужно повторно запросить авторизацию? */
        $gaid = isset($_COOKIE[$wgCookiePrefix.'globalauth']) ? $_COOKIE[$wgCookiePrefix.'globalauth'] : false;
        $d = false;
        if ($wgUser->getId())
        {
            if ($egGlobalAuthWhitelistUsers && in_array($wgUser->getName(), $egGlobalAuthWhitelistUsers))
                return;
            $d = $cache->get(wfMemcKey('ga-udata', $wgUser->getId()));
        }
        if (!$d && $gaid)
        {
            /* если пользователь не имеет локальной учётной записи, проверим внешние группы по ID сессии */
            $d = $cache->get(wfMemcKey('ga-cdata', $gaid));
        }
        /* Инициировать, если
           - запросили перелогин ($force)
           - пользователь не авторизован, а требуется он или внешняя группа
           - пользователь не авторизован и вообще не пробовал авторизоваться, и пришёл к нам браузер, а не LWP какое-нибудь
           - требуется группа, а данные о группах ещё не получены
         */
        $is_browser = preg_match('/Opera|Mozilla|Chrome|Safari|MSIE/is', $_SERVER['HTTP_USER_AGENT']);
        $redo_auth = $force || (!$d && !$gaid) && $is_browser || ($require || $rg) && (!$d || $d == 'nologin') || $rg && (!is_array($d) || !$d['user_groups']);
        if (!$redo_auth)
        {
            if ($rg && !in_array($rg, $d['user_groups']))
                self::group_access_denied($d);
            return;
        }
        /* генерируем ID и ключ */
        $id = unpack('H*', urandom(16));
        $id = $id[1];
        $key = unpack('H*', urandom(16));
        $key = $key[1];
        $url = $egGlobalAuthServer;
        $url .= (strpos($url, '?') !== false ? '&' : '?');
        /* передаём их серверу */
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url."ga_id=$id&ga_key=$key");
        curl_setopt($curl, CURLOPT_TIMEOUT, 30);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        $content = curl_exec($curl);
        $r = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        if ($content)
        {
            $return = self::clean_uri(array('ga_client' => 1));
            $cachekey = wfMemcKey('ga-ckey', $id);
            $cache->set($cachekey, $key, 86400);
            /* Авторизуй меня, Большая Черепаха!!!
               перекидываем на сервер авторизации */
            header("Location: ${url}ga_id=$id&ga_url=".urlencode($return).($require ? "" : "&ga_check=1"));
            exit;
        }
        wfDebug("Global Auth Client: error getting ${url}ga_id=$id&ga_key=$key: HTTP $r, response content:\n$content\n***\n\n");
    }
}
