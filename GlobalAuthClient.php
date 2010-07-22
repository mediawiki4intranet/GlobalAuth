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

/*  Расширение - клиент глобальной авторизации (GlobalAuth.php - сервер глобальной авторизации)
    Конфигурация: 
    $egGlobalAuthServer = '';               // обязательная настройка, URL скрипта сервера авторизации
    $egGlobalAuthClientRequire = false;     // требовать успешной авторизации?
    $egGlobalAuthClientRequireGroup = NULL; // требовать членства пользователя во внешней группе такой-то
                                            // и показывать ошибку $egGlobalAuthGroupAccessDeniedTemplate, если не
    $egGlobalAuthMapToHaloACL = false;      // синхронизировать внешние группы с HaloACL-группами
*/

/* шаблон HTML-сообщения об ошибке доступа по внешней группе */
if (!$egGlobalAuthGroupAccessDeniedTemplate)
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
    /* Спецстраницы, всегда доступные без авторизации */
    static $Whitelist = array(
        'userlogin'     => 1,
        'userlogout'    => 1,
        'confirmemail'  => 1,
    );

    /* Текущий URL минус параметры запроса глобальной авторизации плюс $append, если он не пуст */
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

    /* Обновить HaloACL-группы с суффиксом $suffix, добавив/удалив откуда надо/куда надо пользователя $user */
    static function map_to_haloacl_groups($user, $groups, $suffix)
    {
        global $wgUser;
        $dbr = wfGetDB(DB_SLAVE);
        /* получаем список внешних групп, в которых уже есть $user */
        $res = $dbr->select(array('halo_acl_group_members', 'halo_acl_groups'), 'group_name',
            array(
                'group_name LIKE '.$dbr->addQuotes('%'.$suffix),
                'group_id=parent_group_id',
                'child_type' => 'user',
                'child_id' => $user->getId()
            ),
            __METHOD__
        );
        /* вычисляем разницу между теми, что есть и теми, что надо */
        $add_groups = array();
        foreach ($groups as $g)
            $add_groups[$g.$suffix] = 1;
        $remove_groups = array();
        while ($row = $dbr->fetchRow($res))
        {
            if (!array_key_exists($row, $add_groups))
                $remove_groups[] = $row;
            unset($add_groups[$row]);
        }
        $dbr->freeResult($res);
        $remove_groups = array_flip($remove_groups);
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
        $wgUser = User::newFromName('WikiSysop');
        foreach ($members as $group => $users)
        {
            $content = array();
            foreach ($users as $u => $true)
                $content[] = 'User:'.$u;
            $content =
                "{{#member:members=".implode(',',$content)."}}\n" .
                "{{#manage group:assigned to=User:WikiSysop}}\n" .
                "[[Category:ACL/Group]]";
            $article = new Article(Title::newFromText("ACL:Group/$group"));
            $article->doEdit($content, "Update $group", EDIT_FORCE_BOT);
            /* HACLParserFunctions ругается, если обновлять несколько статей за раз без reset'а */
            HACLParserFunctions::getInstance()->reset();
        }
    }

    /* Хук в MediaWiki */
    static function MediaWikiPerformAction($output, $article, $title, $user, $request, $wiki)
    {
        global $wgUser, $wgRequest;
        global $egGlobalAuthClientRequire, $egGlobalAuthClientRequireGroup, $egGlobalAuthServer, $egGlobalAuthMapToHaloACL;
        if (!$egGlobalAuthServer)
            return true;
        $v = $request->getValues();
        if ($v['ga_client'] && ($id = $v['ga_id']))
        {
            $cache = wfGetCache(CACHE_ANYTHING);
            $cachekey = wfMemcKey('ga-ckey', $id);
            $datakey = wfMemcKey('ga-cdata', $id);
            $secret = $cache->get($cachekey);
            /* сервер передаёт нам данные, их надо сохранить в кэше */
            if ($v['ga_key'] && $v['ga_key'] == $secret)
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
            /* к нам пришёл пользователь, его надо авторизовать или послать */
            if (!$v['ga_key'] && ($d = $cache->get($datakey)))
            {
                $user = self::get_user($d);
                if ($egGlobalAuthClientRequireGroup && !in_array($egGlobalAuthClientRequireGroup, $d['user_groups']))
                    self::group_access_denied($d, $egGlobalAuthClientRequireGroup);
                elseif ($user)
                {
                    if ($egGlobalAuthMapToHaloACL && class_exists('HACLSecurityDescriptor'))
                    {
                        /* нужно отобразить внешние группы на HaloACL-группы */
                        self::map_to_haloacl_groups($user, $d['user_groups'], $d['auth_source'] ? ' ('.$d['auth_source'].')' : ' (X)');
                    }
                    $cache->delete($datakey);
                    $cache->set(wfMemcKey('ga-udata', $user->getId()), $d, 86400);
                    $user->setCookies();
                }
                else
                    $wgRequest->response()->setcookie('globalauth', $id);
                header("Location: ".self::clean_uri());
                exit;
            }
        }
        $spec = strtolower($title->getText());
        if ($title->getNamespace() != NS_SPECIAL || !self::$Whitelist[$spec])
            self::require_auth($egGlobalAuthClientRequire || $_REQUEST['ga_require']);
        return true;
    }

    /* получить локального пользователя по внешним данным $d */
    static function get_user($d)
    {
        $emails = array($d['user_email'] => 1);
        if ($d['user_email_aliases'])
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

    /* инициировать глобальную авторизацию,
       требовать успешную авторизацию при $require,
       инициировать глобальную авторизацию заново при $force */
    static function require_auth($require = false, $force = false)
    {
        global $wgUser, $wgRequest, $wgCookiePrefix;
        global $egGlobalAuthClientRequireGroup, $egGlobalAuthServer;
        if (!$egGlobalAuthServer)
            return;
        $cache = wfGetCache(CACHE_ANYTHING);
        $require = $require || $force;
        $rg = $egGlobalAuthClientRequireGroup;
        /* в каких случаях нужно повторно запросить авторизацию? */
        if ($wgUser->getId())
            $d = $cache->get(wfMemcKey('ga-udata', $wgUser->getId()));
        else
        {
            /* если пользователь не имеет локальной учётной записи, проверим внешние группы по ID сессии */
            $id = $_COOKIE[$wgCookiePrefix.'globalauth'];
            if ($id)
                $d = $cache->get(wfMemcKey('ga-cdata', $id));
        }
        /* Инициировать, если
           - запросили перелогин ($force)
           - пользователь не авторизован, а требуется он или внешняя группа
           - пользователь не авторизован и вообще не пробовал авторизоваться
           - требуется группа, а данные о группах ещё не получены
         */
        $redo_auth = $force || !$d || ($require || $rg) && $d == 'nologin' || $rg && !$d['user_groups'];
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
