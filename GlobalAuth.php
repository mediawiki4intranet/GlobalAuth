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

$wgSpecialPages['GlobalAuth'] = 'SpecialGlobalAuth';

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
        $par = explode('/', $par, 2);
        $id = $par[0] ?: @$v['ga_id'];
        $secret = isset($par[1]) ? $par[1] : false;
        if (!$id)
            die("global auth session ID is missing (_REQUEST[ga_id])");
        if (!$secret)
            $secret = @$v['ga_key'];
        $cache = wfGetCache(CACHE_DB);
        $cachekey = wfMemcKey('ga', $id);
        $urlkey = wfMemcKey('gau', $id);
        if ($secret)
        {
            $cache->add($cachekey, $secret, 86400);
            print "1";
        }
        elseif ($secret = $cache->get($cachekey))
        {
            $url = !empty($v['ga_url']) ? $v['ga_url'] : $cache->get($urlkey);
            if (!$url)
                die("global auth post-back URL is missing (_REQUEST[ga_url])");
            if (!$wgUser->getId() && empty($v['ga_check']))
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
                if (class_exists('IACLDefinition'))
                {
                    $where = array(
                        'child_type' => IACL::PE_USER,
                        'child_id' => $wgUser->getId(),
                        'pe_type' => IACL::PE_GROUP,
                    );
                    $rules = IACLStorage::get('SD')->getRules($where, $options);
                    foreach ($rules as &$rule)
                    {
                        $rule = $rule['pe_id'];
                    }
                    if ($rules)
                    {
                        $dbr = wfGetDB(DB_SLAVE);
                        $rules = $dbr->select('page', 'page_title', array('page_id' => $rules), __METHOD__);
                        foreach ($rules as &$rule)
                        {
                            $rule = str_replace('_', ' ', $rule->page_title);
                        }
                    }
                    $data['user_groups'] = $rules;
                }
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
            if (!empty($v['ga_url']))
            {
                // Просто отправить пользователя назад
                $url = $v['ga_url'];
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
