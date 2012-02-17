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

$wgExtensionFunctions[] = "wfInitGlobalAuth";

function wfInitGlobalAuth()
{
    global $IP;
    require_once("$IP/includes/SpecialPage.php");
    SpecialPage::addPage(new SpecialGlobalAuth);
}

/**

(1) Внешняя система - клиент глобальной авторизации
(2) MediaWiki - сервер глобальной авторизации

(1) генерирует случайный ID (<ID>) и пароль (<KEY>)

(1) [GET-запрос с сервера] -----> (2) ga_id=<ID>&ga_key=<KEY>
(1) [редирект в браузере] ------> (2) ga_id=<ID>&ga_url=<URL_для_передачи_данных_(1)>
&ga_check=0 (требует входа)
  (2) [POST-запрос с сервера] --> (1) ga_id=<ID>&ga_key=<KEY>&ga_data=<ДАННЫЕ_в_JSON>
&ga_check=1 и пользователь не вошёл на сайт сервера авторизации
  (2) [POST-запрос с сервера] --> (1) ga_id=<ID>&ga_key=<KEY>&ga_nologin=1
(2) [редирект в браузере] ------> (1) ga_id=<ID>&ga_res=<КОД_успешности>

Это простейший протокол, который даёт возможность нам сказать
внешней системе, кто к нам вошёл, так, что внешняя система
знает, что это говорим ей именно мы, а мы знаем, что
мы говорим это именно ей.

И ID и ключ являются секретными, но ID знает и пользователь (браузер),
а ключ - только сами сервера.

OpenID, на самом деле, работает похоже.

 */

class SpecialGlobalAuth extends SpecialPage
{
    function __construct()
    {
        parent::__construct('GlobalAuth');
        $this->setListed(false);
    }
    function execute($par)
    {
        global $wgUser, $wgRequest, $wgSitename;
        $v = $wgRequest->getValues();
        list($id, $secret) = explode('/', $par, 2);
        if (!$id && !($id = $v['ga_id']))
            die("global auth session ID is missing (_REQUEST[ga_id])");
        if (!$secret)
            $secret = $v['ga_key'];
        $cache = wfGetCache(CACHE_ANYTHING);
        $cachekey = wfMemcKey('ga', $id);
        $urlkey = wfMemcKey('gau', $id);
        if ($secret)
        {
            $cache->add($cachekey, $v['ga_key'], 86400);
            print "1";
        }
        elseif ($secret = $cache->get($cachekey))
        {
            $url = $v['ga_url'];
            if (!$url)
                $url = $cache->get($urlkey);
            if (!$url)
                die("global auth post-back URL is missing (_REQUEST[ga_url])");
            if (!$wgUser->getId() && !$v['ga_check'])
            {
                $cache->set($urlkey, $url, 86400);
                $url = "Special:GlobalAuth/$id";
                $url = Title::newFromText('Special:UserLogin')->getFullUrl(array('returnto' => $url));
                header("Location: $url");
                exit;
            }
            if ($wgUser->getId())
            {
                $data = array(
                    'user_id'           => $wgUser->getId(),
                    'user_email'        => $wgUser->getEmail(),
                    'user_name'         => $wgUser->getName(),
                    'user_real_name'    => $wgUser->getRealName(),
                    'user_registration' => $wgUser->getRegistration(),
                    'user_rights'       => $wgUser->getAllRights(),
                    'user_options'      => $wgUser->mOptions,
                    'user_url'          => $wgUser->getUserPage()->getFullURL(),
                    'auth_source'       => $wgSitename,
                    'auth_server'       => Title::newFromText('Special:GlobalAuth')->getFullUrl(),
                    'auth_site'         => Title::newMainPage()->getFullUrl(),
                );
                $data = array('ga_data' => json_encode($data));
            }
            else
            {
                /* ga_check=1 => не требовать логина, если не вошёл, сказать что не вошёл */
                $data = array('ga_nologin' => 1);
            }
            $data += array(
                'ga_id' => $id,
                'ga_key' => $secret,
            );
            $curl = curl_init();
            curl_setopt($curl, CURLOPT_URL, $url);
            curl_setopt($curl, CURLOPT_TIMEOUT, 30);
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_exec($curl);
            $r = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            curl_close($curl);
            $url .= (strpos($url, '?') !== false ? '&' : '?');
            $url .= 'ga_id='.urlencode($id).'&ga_res='.$r;
            header("Location: $url");
            $cache->delete($cachekey);
            $cache->delete($urlkey);
        }
        else
        {
            $url = $v['ga_url'];
            if ($url)
            {
                // Просто отправить пользователя назад
                $url .= (strpos($url, '?') !== false ? '&' : '?');
                $url .= 'ga_id='.urlencode($id).'&ga_res=404';
                header("Location: $url");
            }
            else
                die("ga_id points to an unknown global auth session ID");
        }
        exit;
    }
}
