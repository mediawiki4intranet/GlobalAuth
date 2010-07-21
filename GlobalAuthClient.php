<?php

/* Расширение - клиент глобальной авторизации (GlobalAuth.php - сервер глобальной авторизации) */

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

if (!$egGlobalAuthGroupAccessDeniedTemplate)
    $egGlobalAuthGroupAccessDeniedTemplate = '
<html>
<head>
<title>403 Forbidden</title>
</head>
<body>
<h1>Forbidden</h1>
Access to this site is only allowed to users who are members of <b>$egGlobalAuthClientRequireGroup</b> <a href="$d[auth_site]" target="_blank">$d[auth_source]</a> group.<br />
Relogin to <a href="$d[auth_site]">$d[auth_source]</a> with appropriate user first, and then <a href="$relogin_url">click here</a>.
<h1>Доступ запрещён</h1>
Доступ к данному сайту разрешён только членам <a href="$d[auth_site]">$d[auth_source]</a>-группы <b>$egGlobalAuthClientRequireGroup</b>.<br />
Сначала перезайдите в <a href="$d[auth_site]" target="_blank">$d[auth_source]</a> под подходящим именем пользователя, а потом <a href="$relogin_url">нажмите сюда</a>.
</body>
</html>
';

class MWGlobalAuthClient
{
    static function clean_uri($append = array())
    {
        global $wgProto;
        $gp = $_GET+$_POST;
        foreach(explode(' ', 'id key client res nologin data require') as $k)
            unset($gp["ga_$k"]);
        if (trim($_SERVER['PATH_INFO'], '/'))
            unset($gp['title']);
        $uri = $wgProto."://".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
        if (($p = strpos($uri, '?')) !== false)
            $uri = substr($uri, 0, $p);
        $gp += $append;
        if ($gp)
            $uri .= '?'.http_build_query($gp);
        return $uri;
    }

    static function MediaWikiPerformAction($output, $article, $title, $user, $request, $wiki)
    {
        global $wgUser;
        global $egGlobalAuthClientRequire, $egGlobalAuthClientRequireGroup, $egGlobalAuthServer;
        if (!$egGlobalAuthServer)
            return true;
        $v = $request->getValues();
        if ($v['ga_client'] && ($id = $v['ga_id']))
        {
            $cache = wfGetCache(CACHE_ANYTHING);
            $cachekey = wfMemcKey('ga-ckey', $id);
            $datakey = wfMemcKey('ga-cdata', $data);
            $secret = $cache->get($cachekey);
            // получение данных авторизации от сервера
            if ($v['ga_key'] && $v['ga_key'] == $secret)
            {
                $cache->delete($cachekey);
                if ($v['ga_nologin'])
                    $data = 'nologin';
                elseif ($v['ga_data'])
                {
                    $data = (array)json_decode($v['ga_data']);
                    if ($data)
                        $data = json_encode($data);
                }
                if ($data)
                {
                    $cache->set($datakey, $data, 86400);
                    print "1";
                    exit;
                }
            }
            // всё, пришёл пользователь, авторизуем его
            elseif (!$v['ga_key'] && ($d = $cache->get($datakey)))
            {
                if ($d != 'nologin')
                    $d = (array)json_decode($d);
                $emails = array($d['user_email'] => 1);
                if ($d['user_email_aliases'])
                    $emails += array_flip($d['user_email_aliases']);
                $dbr = wfGetDB(DB_SLAVE);
                foreach (array_keys($emails) as $email)
                {
                    if ($userid = $dbr->selectField('user', 'user_id', array('user_email' => $email, 'user_email_confirmed IS NOT NULL'), __METHOD__))
                    {
                        $u = User::newFromId($userid);
                        break;
                    }
                }
                if ($egGlobalAuthClientRequireGroup && !in_array($egGlobalAuthClientRequireGroup, $d['user_groups']))
                    self::group_access_denied($d);
                elseif ($userid)
                {
                    $wgUser = $u;
                    $wgUser->setCookies();
                    $cache->delete($datakey);
                    $cache->set(wfMemcKey('ga-udata', $wgUser->getId()), $d, 86400);
                }
                else
                    $wgRequest->response()->setcookie('globalauth', $id);
                header("Location: ".self::clean_uri());
                exit;
            }
        }
        $spec = strtolower($title->getText());
        if ($title->getNamespace() != NS_SPECIAL ||
            $spec != 'userlogin' && $spec != 'confirmemail')
            self::require_auth($egGlobalAuthClientRequire || $_REQUEST['ga_require']);
        return true;
    }

    static function group_access_denied($d)
    {
        global $egGlobalAuthGroupAccessDeniedTemplate, $egGlobalAuthClientRequireGroup;
        $relogin_url = self::clean_uri(array('ga_require' => 1));
        header("HTTP/1.1 403 Forbidden");
        header("Content-Type: text/html; charset=utf-8");
        print eval('return "'.str_replace(array("\\",'"'),array("\\\\",'\\"'),$egGlobalAuthGroupAccessDeniedTemplate).'";');
        exit;
    }

    static function require_auth($require = false, $force = false)
    {
        global $wgUser, $wgRequest, $wgCookiePrefix;
        global $egGlobalAuthClientRequireGroup, $egGlobalAuthServer;
        if (!$egGlobalAuthServer)
            return;
        $cache = wfGetCache(CACHE_ANYTHING);
        $require = $require || $force;
        $redo_auth = $force;
        if ($egGlobalAuthClientRequireGroup)
        {
            if ($wgUser->getId())
            {
                /* если пользователь вошёл, проверим внешние группы по его ID */
                $d = $cache->get(wfMemcKey('ga-udata', $wgUser->getId()));
                if (!$d || !$d['user_groups'])
                    $redo_auth = true;
                elseif (!in_array($egGlobalAuthClientRequireGroup, $d['user_groups']))
                    self::group_access_denied($d);
            }
            elseif (($id = $_COOKIE[$wgCookiePrefix.'globalauth']) &&
                ($d = $cache->get(wfMemcKey('ga-cdata', $id))))
            {
                /* если пользователь не имеет локальной учётной записи, проверим внешние группы по ID сессии */
                if (!$d['user_groups'])
                    $redo_auth = true;
                elseif (!in_array($egGlobalAuthClientRequireGroup, $d['user_groups']))
                    self::group_access_denied($d);
            }
            else
            {
                /* иначе нужно авторизоваться заново */
                $redo_auth = true;
            }
        }
        if (!$wgUser->getId() && ($require || !$_COOKIE[$wgCookiePrefix.'redoglobalauth']))
            $redo_auth = true;
        if (!$redo_auth)
            return;
        $id = unpack('H*', urandom(16));
        $id = $id[1];
        $key = unpack('H*', urandom(16));
        $key = $key[1];
        $url = $egGlobalAuthServer;
        $url .= (strpos($url, '?') !== false ? '&' : '?');
            $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url."ga_id=$id&ga_key=$key");
        curl_setopt($curl, CURLOPT_TIMEOUT, 30);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        $content = curl_exec($curl);
        $r = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        $wgRequest->response()->setcookie('redoglobalauth', 1);
        if ($content)
        {
            $return = self::clean_uri(array('ga_client' => 1));
            $cachekey = wfMemcKey('ga-ckey', $id);
            $cache->set($cachekey, $key, 86400);
            // Авторизуй меня, Большая Черепаха!!!
            header("Location: ${url}ga_id=$id&ga_url=".urlencode($return).($require ? "" : "&ga_check=1"));
            exit;
        }
        wfDebug("Global Auth Client: error getting ${url}ga_id=$id&ga_key=$key: HTTP $r, response content:\n$content\n***\n\n");
    }
}
