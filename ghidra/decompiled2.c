===== get_auth_msg @ 0000a0f0 ===== (GhidraScript)  
undefined4
_get_auth_msg(int param_1,long param_2,undefined8 param_3,undefined8 param_4,char *param_5,
             undefined8 param_6,char *param_7,undefined8 param_8,undefined8 param_9)

{
  undefined4 uVar1;
  int iVar2;
  size_t sVar3;
  char *pcVar4;
  size_t sVar5;
  size_t sVar6;
  undefined8 in_stack_ffffffffffffccc0;
  undefined4 uVar7;
  undefined8 in_stack_ffffffffffffcce0;
  undefined4 uVar8;
  undefined4 local_315c;
  char local_3158 [4128];
  char local_2138 [256];
  undefined1 local_2038 [4096];
  undefined1 local_1038 [4104];
  long local_30;
  
  uVar8 = (undefined4)((ulong)in_stack_ffffffffffffcce0 >> 0x20);
  uVar7 = (undefined4)((ulong)in_stack_ffffffffffffccc0 >> 0x20);
  local_30 = *(long *)PTR____stack_chk_guard_002e4060;
  _memset(local_1038,0,0x1000);
  _memset(local_2038,0,0x1000);
  if ((param_2 == 0) || (param_5 == (char *)0x0)) {
    if (_array_vpn_log_level_ < 4) {
      _array_vpn_logprint(3,"aaa.c",0x596,"get_auth_msg: sess is null. return.\n");
    }
    local_315c = 0;
  }
  else {
    _memset(local_2138,0,0x100);
    _array_get_spa_sess(local_2138);
    _memset(local_3158,0,0x1020);
    if (_g_printlogtraffic == 0) {
      if (_array_vpn_log_level_ < 2) {
        sVar3 = _strlen((char *)(param_2 + 0x2a0));
        sVar5 = _strlen(&_g_otp_code_cookie);
        _array_vpn_logprint(1,"aaa.c",0x5a4,
                            "get_auth_msg: session cookie length: %d, otp code cookie length: %d\n",
                            sVar3,sVar5);
      }
    }
    else if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x5a0,"get_auth_msg: session cookie:%s, otp code cookie: %s\n",
                          param_2 + 0x2a0,&_g_otp_code_cookie);
    }
    sVar3 = _strlen(&_g_otp_code_cookie);
    if ((((sVar3 == 0) || (pcVar4 = _strstr(&_g_otp_code_cookie,"ANsession"), pcVar4 == (char *)0x0)
         ) || (pcVar4 = _strstr(&_g_otp_code_cookie,"="), pcVar4 == (char *)0x0)) ||
       (pcVar4 = _strstr(&_g_otp_code_cookie,"+"), pcVar4 == (char *)0x0)) {
      ___snprintf_chk(local_3158,&DAT_0000101f,0,&DAT_00001020,"%s",param_2 + 0x2a0);
    }
    else {
      ___snprintf_chk(local_3158,&DAT_0000101f,0,&DAT_00001020,"%s",&_g_otp_code_cookie);
    }
    iVar2 = _is_ipv6_host(param_2 + 0x9c);
    if (iVar2 == 0) {
      if (param_1 == 3) {
        pcVar4 = _strstr(param_5,"MAuthServer");
        if (((pcVar4 == (char *)0x0) || (pcVar4 = _strstr(param_5,"qrcode"), pcVar4 == (char *)0x0))
           || (pcVar4 = _strstr(param_5,"business="), pcVar4 == (char *)0x0)) {
          pcVar4 = _strstr(param_5,"?");
          if (pcVar4 == (char *)0x0) {
            ___snprintf_chk(local_1038,0xfff,0,0x1000,
                            "GET %s?%s HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                            ,param_5,param_7,param_2 + 0x9c,*(undefined4 *)(param_2 + 0x29c),param_6
                            ,param_2 + 0x2a0,local_2138);
            uVar7 = *(undefined4 *)(param_2 + 0x29c);
            sVar3 = _strlen((char *)(param_2 + 0x2a0));
            sVar5 = _strlen(local_2138);
            ___snprintf_chk(local_2038,0xfff,0,0x1000,
                            "GET %s?%s HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session_len=%d\r\nContent-Type: application/json\r\n\r\n"
                            ,param_5,param_7,param_2 + 0x9c,uVar7,param_6,sVar3,sVar5);
          }
          else {
            ___snprintf_chk(local_1038,0xfff,0,0x1000,
                            "GET %s&%s HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                            ,param_5,param_7,param_2 + 0x9c,*(undefined4 *)(param_2 + 0x29c),param_6
                            ,param_2 + 0x2a0,local_2138);
            uVar7 = *(undefined4 *)(param_2 + 0x29c);
            sVar3 = _strlen((char *)(param_2 + 0x2a0));
            sVar5 = _strlen(local_2138);
            ___snprintf_chk(local_2038,0xfff,0,0x1000,
                            "GET %s&%s HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session_len=%d\r\nContent-Type: application/json\r\n\r\n"
                            ,param_5,param_7,param_2 + 0x9c,uVar7,param_6,sVar3,sVar5);
          }
        }
        else {
          ___snprintf_chk(local_1038,0xfff,0,0x1000,
                          "GET %s%s HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                          ,param_5,param_7,param_2 + 0x9c,*(undefined4 *)(param_2 + 0x29c),param_6,
                          param_2 + 0x2a0,local_2138);
          uVar7 = *(undefined4 *)(param_2 + 0x29c);
          sVar3 = _strlen((char *)(param_2 + 0x2a0));
          sVar5 = _strlen(local_2138);
          ___snprintf_chk(local_2038,0xfff,0,0x1000,
                          "GET %s%s HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session_len=%d\r\nContent-Type: application/json\r\n\r\n"
                          ,param_5,param_7,param_2 + 0x9c,uVar7,param_6,sVar3,sVar5);
        }
      }
      else if (param_1 == 2) {
        uVar1 = *(undefined4 *)(param_2 + 0x29c);
        sVar3 = _strlen(param_7);
        ___snprintf_chk(local_1038,0xfff,0,0x1000,
                        "POST %s HTTP/1.1\r\nHost: %s:%u\r\naccess_token: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s"
                        ,param_5,param_2 + 0x9c,CONCAT44(uVar7,uVar1),param_6,param_2 + 0x2a0,
                        local_2138,CONCAT44(uVar8,(int)sVar3),param_7);
        uVar7 = *(undefined4 *)(param_2 + 0x29c);
        sVar3 = _strlen((char *)(param_2 + 0x2a0));
        sVar5 = _strlen(local_2138);
        sVar6 = _strlen(param_7);
        ___snprintf_chk(local_2038,0xfff,0,0x1000,
                        "POST %s HTTP/1.1\r\nHost: %s:%u\r\naccess_token: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session_len=%d\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s"
                        ,param_5,param_2 + 0x9c,uVar7,param_6,sVar3,sVar5,sVar6 & 0xffffffff,param_7
                       );
      }
      else {
        uVar1 = *(undefined4 *)(param_2 + 0x29c);
        sVar3 = _strlen(param_7);
        ___snprintf_chk(local_1038,0xfff,0,0x1000,
                        "POST %s HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s"
                        ,param_5,param_2 + 0x9c,CONCAT44(uVar7,uVar1),param_6,local_3158,local_2138,
                        CONCAT44(uVar8,(int)sVar3),param_7);
        uVar7 = *(undefined4 *)(param_2 + 0x29c);
        sVar3 = _strlen(local_3158);
        sVar5 = _strlen(local_2138);
        sVar6 = _strlen(param_7);
        ___snprintf_chk(local_2038,0xfff,0,0x1000,
                        "POST %s HTTP/1.1\r\nHost: %s:%u\r\nAuthorization: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session_len=%d\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s"
                        ,param_5,param_2 + 0x9c,uVar7,param_6,sVar3,sVar5,sVar6 & 0xffffffff,param_7
                       );
      }
    }
    else if (param_1 == 3) {
      pcVar4 = _strstr(param_5,"MAuthServer");
      if (((pcVar4 == (char *)0x0) || (pcVar4 = _strstr(param_5,"qrcode"), pcVar4 == (char *)0x0))
         || (pcVar4 = _strstr(param_5,"business="), pcVar4 == (char *)0x0)) {
        pcVar4 = _strstr(param_5,"?");
        if (pcVar4 == (char *)0x0) {
          ___snprintf_chk(local_1038,0xfff,0,0x1000,
                          "GET %s?%s HTTP/1.1\r\nHost: [%s]:%u\r\nAuthorization: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                          ,param_5,param_7,param_2 + 0x9c,*(undefined4 *)(param_2 + 0x29c),param_6,
                          param_2 + 0x2a0,local_2138);
          uVar7 = *(undefined4 *)(param_2 + 0x29c);
          sVar3 = _strlen((char *)(param_2 + 0x2a0));
          ___snprintf_chk(local_2038,0xfff,0,0x1000,
                          "GET %s?%s HTTP/1.1\r\nHost: [%s]:%u\r\nAuthorization: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                          ,param_5,param_7,param_2 + 0x9c,uVar7,param_6,sVar3,local_2138);
        }
        else {
          ___snprintf_chk(local_1038,0xfff,0,0x1000,
                          "GET %s&%s HTTP/1.1\r\nHost: [%s]:%u\r\nAuthorization: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                          ,param_5,param_7,param_2 + 0x9c,*(undefined4 *)(param_2 + 0x29c),param_6,
                          param_2 + 0x2a0,local_2138);
          uVar7 = *(undefined4 *)(param_2 + 0x29c);
          sVar3 = _strlen((char *)(param_2 + 0x2a0));
          ___snprintf_chk(local_2038,0xfff,0,0x1000,
                          "GET %s&%s HTTP/1.1\r\nHost: [%s]:%u\r\nAuthorization: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                          ,param_5,param_7,param_2 + 0x9c,uVar7,param_6,sVar3,local_2138);
        }
      }
      else {
        ___snprintf_chk(local_1038,0xfff,0,0x1000,
                        "GET %s%s HTTP/1.1\r\nHost: [%s]:%u\r\nAuthorization: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                        ,param_5,param_7,param_2 + 0x9c,*(undefined4 *)(param_2 + 0x29c),param_6,
                        param_2 + 0x2a0,local_2138);
        uVar7 = *(undefined4 *)(param_2 + 0x29c);
        sVar3 = _strlen((char *)(param_2 + 0x2a0));
        ___snprintf_chk(local_2038,0xfff,0,0x1000,
                        "GET %s%s HTTP/1.1\r\nHost: [%s]:%u\r\nAuthorization: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\n\r\n"
                        ,param_5,param_7,param_2 + 0x9c,uVar7,param_6,sVar3,local_2138);
      }
    }
    else if (param_1 == 2) {
      uVar1 = *(undefined4 *)(param_2 + 0x29c);
      sVar3 = _strlen(param_7);
      ___snprintf_chk(local_1038,0xfff,0,0x1000,
                      "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\naccess_token: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s"
                      ,param_5,param_2 + 0x9c,CONCAT44(uVar7,uVar1),param_6,param_2 + 0x2a0,
                      local_2138,CONCAT44(uVar8,(int)sVar3),param_7);
      uVar7 = *(undefined4 *)(param_2 + 0x29c);
      sVar3 = _strlen((char *)(param_2 + 0x2a0));
      sVar5 = _strlen(param_7);
      ___snprintf_chk(local_2038,0xfff,0,0x1000,
                      "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\naccess_token: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s"
                      ,param_5,param_2 + 0x9c,uVar7,param_6,sVar3,local_2138,sVar5 & 0xffffffff,
                      param_7);
    }
    else {
      uVar1 = *(undefined4 *)(param_2 + 0x29c);
      sVar3 = _strlen(param_7);
      ___snprintf_chk(local_1038,0xfff,0,0x1000,
                      "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\nAuthorization: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s"
                      ,param_5,param_2 + 0x9c,CONCAT44(uVar7,uVar1),param_6,local_3158,local_2138,
                      CONCAT44(uVar8,(int)sVar3),param_7);
      uVar7 = *(undefined4 *)(param_2 + 0x29c);
      sVar3 = _strlen(local_3158);
      sVar5 = _strlen(param_7);
      ___snprintf_chk(local_2038,0xfff,0,0x1000,
                      "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\nAuthorization: %s\r\nCookie: sess_len:%d;ANStandalone=true;SPA-Session=%s\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s"
                      ,param_5,param_2 + 0x9c,uVar7,param_6,sVar3,local_2138,sVar5 & 0xffffffff,
                      param_7);
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x607,"get_auth_msg: req no sess: \n[%s]\n",local_2038);
    }
    local_315c = _ssl_get_page_auto_malloc_real_len(param_2,local_1038,param_8,param_9);
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_30) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return local_315c;
}

 (GhidraScript)  
===== build_login_req @ 00012de0 ===== (GhidraScript)  
undefined4 _build_login_req(long param_1,long param_2,int param_3,long *param_4,long param_5)

{
  long lVar1;
  __uint16_t _Var2;
  undefined4 uVar3;
  int iVar4;
  size_t sVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  char *pcVar8;
  size_t sVar9;
  size_t sVar10;
  void *pvVar11;
  size_t sVar12;
  size_t sVar13;
  size_t sVar14;
  char *pcStack_12b50;
  uint uStack_12b30;
  char *pcStack_12ab8;
  uint uStack_12a98;
  char *pcStack_12a30;
  uint uStack_12a10;
  char *pcStack_129b0;
  uint uStack_12990;
  char *pcStack_12928;
  char *pcStack_128f8;
  char *pcStack_128d0;
  char *pcStack_128a0;
  char *pcStack_12868;
  uint uStack_1285c;
  undefined4 uStack_1282c;
  undefined1 auStack_12828 [256];
  char acStack_12728 [8192];
  undefined1 auStack_10728 [112];
  undefined1 auStack_106b8 [112];
  undefined1 auStack_10648 [112];
  char acStack_105d8 [8192];
  char local_e5d8 [1552];
  undefined1 local_dfc8 [768];
  undefined1 local_dcc8 [784];
  undefined1 local_d9b8 [784];
  undefined1 local_d6a8 [784];
  undefined1 local_d398 [784];
  undefined1 local_d088 [768];
  char local_cd88 [768];
  undefined1 local_ca88 [768];
  undefined1 local_c788 [256];
  undefined1 local_c688 [768];
  char local_c388 [12304];
  char local_9378 [12304];
  char local_6368 [12304];
  char local_3358 [12304];
  undefined1 local_348 [784];
  long local_38;
  
  local_38 = *(long *)PTR____stack_chk_guard_002e4060;
  _memset(local_348,0,0x301);
  _memset(local_3358,0,0x3001);
  _memset(local_6368,0,0x3001);
  _memset(local_9378,0,0x3001);
  _memset(local_c388,0,0x3001);
  _memset(local_c688,0,0x2fe);
  _memset(local_c788,0,0x100);
  _memset(local_ca88,0,0x2fe);
  _memset(local_cd88,0,0x2fe);
  _memset(local_d088,0,0x2fe);
  _memset(local_d398,0,0x307);
  _memset(local_d6a8,0,0x307);
  _memset(local_d9b8,0,0x307);
  _memset(local_dcc8,0,0x307);
  _memset(local_dfc8,0,0x2fe);
  _memset(local_e5d8,0,0x601);
  _memset(acStack_105d8,0,0x2000);
  _memset(auStack_10648,0,100);
  _memset(auStack_106b8,0,100);
  _memset(auStack_10728,0,100);
  _memset(acStack_12728,0,0x2000);
  *param_4 = 0;
  if (param_2 != 0) {
    _set_dummy_password(param_2,param_1);
    _url_escape(param_2,local_e5d8);
  }
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"aaa.c",0x394,
                        "build_login_req: aaa_info->enable_base64:%d, BASE64_ENCODE_UNAME:%d\n",
                        *(undefined1 *)(param_5 + 0x163e9),0);
  }
  if (*(char *)(param_5 + 0x163e9) == '\0') {
    _url_escape(&UNK_00001501 + param_1,local_348);
    pcVar8 = _strstr(&DAT_00001602 + param_1,
                     "@@-xyz-!this!-@is@-#for#-$mpdeviceid$-%testing%-^&*()_+array");
    if (pcVar8 == (char *)0x0) {
      _url_escape(&DAT_00001602 + param_1,local_6368);
    }
    else {
      sVar5 = _strlen(&UNK_00002603 + param_1);
      if (sVar5 == 0) {
        sVar5 = _strlen(&UNK_00003604 + param_1);
        if (sVar5 == 0) {
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"aaa.c",0x3b0,"detect dummy is running, we use mima as mima.\n");
          }
          _url_escape(&DAT_00001602 + param_1,local_6368);
        }
        else {
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"aaa.c",0x3ab,"detect dummy is running, we use mima3 as mima.\n");
          }
          _url_escape(&UNK_00003604 + param_1,local_6368);
        }
      }
      else {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x3a6,"detect dummy is running, we use mima2 as mima.\n");
        }
        _url_escape(&UNK_00002603 + param_1,local_6368);
      }
    }
  }
  else {
    sVar5 = _strlen(&UNK_00001501 + param_1);
    uVar6 = _base64_encode(&UNK_00001501 + param_1,sVar5);
    sVar5 = _strlen(&DAT_00001602 + param_1);
    uVar7 = _base64_encode(&DAT_00001602 + param_1,sVar5);
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x399,"base64_encode uname:%s\n",uVar6);
    }
    _url_escape(uVar6,local_348);
    _url_escape(uVar7,local_6368);
  }
  pcVar8 = _strstr(&UNK_00002603 + param_1,
                   "@@-xyz-!this!-@is@-#for#-$mpdeviceid$-%testing%-^&*()_+array");
  if (pcVar8 == (char *)0x0) {
    _url_escape(&UNK_00002603 + param_1,local_9378);
  }
  else {
    sVar5 = _strlen(&DAT_00001602 + param_1);
    if (sVar5 == 0) {
      sVar5 = _strlen(&UNK_00003604 + param_1);
      if (sVar5 == 0) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x3c9,"detect dummy is running, we use mima1 as mima1.\n");
        }
        _url_escape(&UNK_00002603 + param_1,local_9378);
      }
      else {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x3c4,"detect dummy is running, we use mima3 as mima1.\n");
        }
        _url_escape(&UNK_00003604 + param_1,local_9378);
      }
    }
    else {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x3bf,"detect dummy is running, we use mima as mima1.\n");
      }
      _url_escape(&DAT_00001602 + param_1,local_9378);
    }
  }
  pcVar8 = _strstr(&UNK_00003604 + param_1,
                   "@@-xyz-!this!-@is@-#for#-$mpdeviceid$-%testing%-^&*()_+array");
  if (pcVar8 == (char *)0x0) {
    _url_escape(&UNK_00003604 + param_1,local_c388);
  }
  else {
    sVar5 = _strlen(&DAT_00001602 + param_1);
    if (sVar5 == 0) {
      sVar5 = _strlen(&UNK_00002603 + param_1);
      if (sVar5 == 0) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x3e1,"detect dummy is running, we use mima3 as mima3.\n");
        }
        _url_escape(&UNK_00003604 + param_1,local_c388);
      }
      else {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x3dc,"detect dummy is running, we use mima2 as mima3.\n");
        }
        _url_escape(&UNK_00002603 + param_1,local_c388);
      }
    }
    else {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x3d7,"detect dummy is running, we use mima as mima3.\n");
      }
      _url_escape(&DAT_00001602 + param_1,local_c388);
    }
  }
  _url_escape(param_1 + 0x4e05,local_c688);
  _url_escape(param_1 + 0x5106,local_cd88);
  _url_escape(&UNK_00004f05 + param_1,local_ca88);
  _url_escape(param_1 + 0x4a05,local_3358);
  _url_escape(param_1 + 0x5206);
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"aaa.c",0x3fb,"client flag=%d\n",*(undefined4 *)(param_1 + 0x84a4));
  }
  if ((*(char *)(param_1 + 0x84a0) != '\0') &&
     (___sprintf_chk(local_d398,0,0x307,"&ext1=%s",local_d088), _array_vpn_log_level_ < 2)) {
    _array_vpn_logprint(1,"aaa.c",0x3fe,"post ext1=%s\n",param_1 + 0x5206);
  }
  if ((*(uint *)(param_1 + 0x84a4) & 2) != 0) {
    _array_vpn_get_current_os_version(auStack_10728,100);
    _array_vpn_get_current_mp_version(auStack_106b8,100);
    uVar3 = _array_vpn_get_current_dev_type();
    ___sprintf_chk(local_dcc8,0,0x307,"mpversion=%s@ostype=%d@osversion=%s@msmodel=",auStack_106b8,
                   uVar3,auStack_10728);
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x408,"post ext2=%s\n",local_dcc8);
    }
    _url_escape(local_dcc8);
    ___sprintf_chk(local_d6a8,0,0x307,"&ext2=%s",local_dfc8);
  }
  _memset(local_d9b8,0,0x307);
  if (param_2 != 0) {
    sVar5 = _strlen((char *)(param_1 + 0xbdd0));
    if ((sVar5 != 0) && (sVar5 = _strlen((char *)(param_1 + 0xcdd1)), sVar5 != 0)) {
      ___snprintf_chk(local_d9b8,0x306,0,0x307,"&uuid=%s&vscode=%s&submitted=true",param_1 + 0xcdd1,
                      param_1 + 0xbdd0);
    }
    if (((*(int *)(param_2 + 0x804) == 0xe) &&
        (sVar5 = _strlen((char *)(param_1 + 0xdfd2)), sVar5 != 0)) &&
       (sVar5 = _strlen((char *)(param_1 + 0xe0d2)), sVar5 != 0)) {
      ___snprintf_chk(local_d9b8,0x306,0,0x307,"&mobile=%s&smscode=%s&submitted=true",
                      param_1 + 0xdfd2,param_1 + 0xe0d2);
    }
    if ((*(int *)(param_2 + 0x804) == 0xf) &&
       (sVar5 = _strlen((char *)(param_1 + 0xe5f3)), sVar5 != 0)) {
      ___snprintf_chk(local_d9b8,0x306,0,0x307,"&random=%s&submitted=true",param_1 + 0xe5f3);
    }
    if (*(int *)(param_2 + 0x804) == 0xd) {
      sVar5 = _strlen(&_g_an_qr_uuid);
      if (sVar5 == 0) {
        sVar5 = _strlen((char *)(param_1 + 0xcdd1));
        if (sVar5 != 0) {
          ___snprintf_chk(local_d9b8,0x306,0,0x307,"&uuid=%s&submitted=true",param_1 + 0xcdd1);
        }
      }
      else {
        ___snprintf_chk(local_d9b8,0x306,0,0x307,"&uuid=%s&submitted=true",&_g_an_qr_uuid);
      }
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x42e,"post zt info=%s\n",local_d9b8);
    }
  }
  ___strncpy_chk(local_c788,local_c688,0xff,0x100);
  sVar5 = _strlen(local_6368);
  if (sVar5 < 0x101) {
    sVar5 = _strlen(local_3358);
    if (sVar5 == 0) {
      if (param_2 == 0) {
        pcStack_128d0 = "";
      }
      else {
        pcStack_128d0 = local_e5d8;
      }
      uStack_1285c = ___snprintf_chk(acStack_105d8,0x1fff,0,0x2000,
                                     "method=%s&uname=%s&pwd=%s&pwd1=%s&pwd2=%s&deviceid=%s&device_name=%s&hardwareid=%s%s%s%s&customer1=%s"
                                     ,pcStack_128d0,local_348,local_6368,local_9378,local_c388,
                                     local_c788,local_ca88,local_cd88,local_d398,local_d6a8,
                                     local_d9b8,param_1 + 0x4605);
    }
    else {
      if (param_2 == 0) {
        pcStack_128a0 = "";
      }
      else {
        pcStack_128a0 = local_e5d8;
      }
      uStack_1285c = ___snprintf_chk(acStack_105d8,0x1fff,0,0x2000,
                                     "method=%s&valid=%s&uname=%s&pwd=%s&pwd1=%s&pwd2=%s&deviceid=%s&device_name=%s&hardwareid=%s%s%s%s&customer1=%s"
                                     ,pcStack_128a0,local_3358,local_348,local_6368,local_9378,
                                     local_c388,local_c788,local_ca88,local_cd88,local_d398,
                                     local_d6a8,local_d9b8,param_1 + 0x4605);
    }
  }
  else {
    sVar5 = _strlen(local_3358);
    if (sVar5 == 0) {
      if (param_2 == 0) {
        pcStack_12928 = "";
      }
      else {
        pcStack_12928 = local_e5d8;
      }
      uStack_1285c = ___snprintf_chk(acStack_105d8,0x1fff,0,0x2000,
                                     "method=%s&uname=%s&long_cred=%s&pwd1=%s&pwd2=%s&deviceid=%s&device_name=%s&hardwareid=%s%s%s%s&customer1=%s"
                                     ,pcStack_12928,local_348,local_6368,local_9378,local_c388,
                                     local_c788,local_ca88,local_cd88,local_d398,local_d6a8,
                                     local_d9b8,param_1 + 0x4605);
    }
    else {
      if (param_2 == 0) {
        pcStack_128f8 = "";
      }
      else {
        pcStack_128f8 = local_e5d8;
      }
      uStack_1285c = ___snprintf_chk(acStack_105d8,0x1fff,0,0x2000,
                                     "method=%s&valid=%s&uname=%s&long_cred=%s&pwd1=%s&pwd2=%s&deviceid=%s&device_name=%s&hardwareid=%s%s%s%s&customer1=%s"
                                     ,pcStack_128f8,local_3358,local_348,local_6368,local_9378,
                                     local_c388,local_c788,local_ca88,local_cd88,local_d398,
                                     local_d6a8,local_d9b8,param_1 + 0x4605);
    }
  }
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"aaa.c",0x452,
                        "username=%s, validcode=%s, method=%s, ext1=%s, ext2=%s, customer1=%s\n",
                        local_348,local_3358,local_e5d8,local_d088,local_d6a8,param_1 + 0x4605);
  }
  sVar5 = _strlen((char *)(param_1 + 0x2a0));
  sVar9 = _strlen((char *)(param_1 + 0x9c));
  sVar10 = _strlen((char *)(param_1 + 0x817f));
  pvVar11 = _calloc(1,uStack_1285c + sVar5 + sVar9 + sVar10 + 0x200);
  *param_4 = (long)pvVar11;
  if (*param_4 == 0) {
    uStack_1282c = 8;
  }
  else {
    if (*(char *)(param_1 + 0xe3f2) == '\x01') {
      pcStack_12868 = "/prx/000/http/localhost/acslogin";
    }
    else {
      pcStack_12868 = "/prx/000/http/localhost/login";
      if (param_3 != 0) {
        pcStack_12868 = "/prx/000/http/localhost/register";
      }
    }
    _memset(auStack_12828,0,0x100);
    _array_get_spa_sess(auStack_12828,0x100);
    if (_g_printlogtraffic == 0) {
      if (_array_vpn_log_level_ < 2) {
        sVar5 = _strlen(&_g_otp_code_cookie);
        _array_vpn_logprint(1,"aaa.c",0x469,"build_login_req: otp code cookie length: %d\n",sVar5);
      }
    }
    else if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x465,"build_login_req: otp code cookie: %s\n",
                          &_g_otp_code_cookie);
    }
    sVar5 = _strlen(&_g_otp_code_cookie);
    if (((sVar5 == 0) || (pcVar8 = _strstr(&_g_otp_code_cookie,"ANsession"), pcVar8 == (char *)0x0))
       || ((pcVar8 = _strstr(&_g_otp_code_cookie,"="), pcVar8 == (char *)0x0 ||
           (pcVar8 = _strstr(&_g_otp_code_cookie,"+"), pcVar8 == (char *)0x0)))) {
      if (*(char *)(param_1 + 0x817f) == '\0') {
        ___snprintf_chk(acStack_12728,0x1fff,0,0x2000,
                        "Cookie: %sANStandalone=true;SPA-Session=%s;%s",param_1 + 0x7f7f,
                        auStack_12828,param_1 + 0x2a0);
      }
      else {
        ___snprintf_chk(acStack_12728,0x1fff,0,0x2000,
                        "Cookie: %sANStandalone=true;SPA-Session=%s;%sNSCOOKIE%%3Blocalhost%%3B%%2F%%3BAN_CLIENTSEC=%s"
                        ,param_1 + 0x7f7f,auStack_12828,param_1 + 0x2a0,param_1 + 0x817f);
      }
    }
    else if (*(char *)(param_1 + 0x817f) == '\0') {
      ___snprintf_chk(acStack_12728,0x1fff,0,0x2000,"Cookie: %sANStandalone=true;SPA-Session=%s;%s",
                      param_1 + 0x7f7f,auStack_12828,&_g_otp_code_cookie);
    }
    else {
      ___snprintf_chk(acStack_12728,0x1fff,0,0x2000,
                      "Cookie: %sANStandalone=true;SPA-Session=%s;%sNSCOOKIE%%3Blocalhost%%3B%%2F%%3BAN_CLIENTSEC=%s"
                      ,param_1 + 0x7f7f,auStack_12828,&_g_otp_code_cookie,param_1 + 0x817f);
    }
    _memset(&_g_otp_code_cookie,0,0x400);
    iVar4 = _is_ipv6_host(param_1 + 0x9c);
    if (iVar4 == 0) {
      lVar1 = *param_4;
      uVar3 = *(undefined4 *)(param_1 + 0x29c);
      sVar5 = _strlen(acStack_105d8);
      ___sprintf_chk(lVar1,0,0xffffffffffffffff,
                     "POST %s HTTP/1.1\r\nHost: %s:%u\r\n%s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\n%s"
                     ,pcStack_12868,param_1 + 0x9c,uVar3,acStack_12728,param_1 + 0x837f,
                     sVar5 & 0xffffffff,acStack_105d8);
      if (_g_printlogtraffic == 0) {
        if (_array_vpn_log_level_ < 2) {
          _Var2 = __OSSwapInt16(*(__uint16_t *)(param_1 + 6));
          if (_Var2 == 0) {
            uStack_12b30 = *(uint *)(param_1 + 0x29c);
          }
          else {
            _Var2 = __OSSwapInt16(*(__uint16_t *)(param_1 + 6));
            uStack_12b30 = (uint)_Var2;
          }
          sVar5 = _strlen(acStack_105d8);
          if (param_2 == 0) {
            pcStack_12b50 = "";
          }
          else {
            pcStack_12b50 = local_e5d8;
          }
          sVar9 = _strlen(local_6368);
          sVar10 = _strlen(local_9378);
          sVar12 = _strlen(local_c388);
          sVar13 = _strlen(local_cd88);
          sVar14 = _strlen(acStack_12728);
          _array_vpn_logprint(1,"aaa.c",0x4a0,
                              "POST %s HTTP/1.1\r\nHost: %s:%u\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\nmethod=%s&valid=%s&uname=%s&mima=***(%d)&mima1=***(%d)&mima2=***(%d)&deviceid=%s&device_name=%s&hardwareid=**********(hwid_len:%d)%s%s%s&customer1=%s, sess_len:%d\n"
                              ,pcStack_12868,param_1 + 0x9c,uStack_12b30,param_1 + 0x837f,
                              sVar5 & 0xffffffff,pcStack_12b50,local_3358,local_348,sVar9,sVar10,
                              sVar12,local_c788,local_ca88,sVar13,local_d398,local_d6a8,local_d9b8,
                              param_1 + 0x4605,sVar14);
        }
      }
      else if (_array_vpn_log_level_ < 2) {
        _Var2 = __OSSwapInt16(*(__uint16_t *)(param_1 + 6));
        if (_Var2 == 0) {
          uStack_12a98 = *(uint *)(param_1 + 0x29c);
        }
        else {
          _Var2 = __OSSwapInt16(*(__uint16_t *)(param_1 + 6));
          uStack_12a98 = (uint)_Var2;
        }
        sVar5 = _strlen(acStack_105d8);
        if (param_2 == 0) {
          pcStack_12ab8 = "";
        }
        else {
          pcStack_12ab8 = local_e5d8;
        }
        sVar9 = _strlen(local_6368);
        sVar10 = _strlen(local_9378);
        sVar12 = _strlen(local_c388);
        sVar13 = _strlen(acStack_12728);
        _array_vpn_logprint(1,"aaa.c",0x49b,
                            "POST %s HTTP/1.1\r\nHost: %s:%u\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\nmethod=%s&valid=%s&uname=%s&mima=%s(%d)&mima1=%s(%d)&mima2=%s(%d)&deviceid=%s&device_name=%s&hardwareid=%s%s%s%s&customer1=%s, sess_len:%d\n"
                            ,pcStack_12868,param_1 + 0x9c,uStack_12a98,param_1 + 0x837f,
                            sVar5 & 0xffffffff,pcStack_12ab8,local_3358,local_348,local_6368,sVar9,
                            local_9378,sVar10,local_c388,sVar12,local_c788,local_ca88,local_cd88,
                            local_d398,local_d6a8,local_d9b8,param_1 + 0x4605,sVar13);
      }
    }
    else {
      lVar1 = *param_4;
      uVar3 = *(undefined4 *)(param_1 + 0x29c);
      sVar5 = _strlen(acStack_105d8);
      ___sprintf_chk(lVar1,0,0xffffffffffffffff,
                     "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\n%s\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\n%s"
                     ,pcStack_12868,param_1 + 0x9c,uVar3,acStack_12728,param_1 + 0x837f,
                     sVar5 & 0xffffffff,acStack_105d8);
      if (_g_printlogtraffic == 0) {
        if (_array_vpn_log_level_ < 2) {
          _Var2 = __OSSwapInt16(*(__uint16_t *)(param_1 + 6));
          if (_Var2 == 0) {
            uStack_12a10 = *(uint *)(param_1 + 0x29c);
          }
          else {
            _Var2 = __OSSwapInt16(*(__uint16_t *)(param_1 + 6));
            uStack_12a10 = (uint)_Var2;
          }
          sVar5 = _strlen(acStack_105d8);
          if (param_2 == 0) {
            pcStack_12a30 = "";
          }
          else {
            pcStack_12a30 = local_e5d8;
          }
          sVar9 = _strlen(local_cd88);
          sVar10 = _strlen(acStack_12728);
          _array_vpn_logprint(1,"aaa.c",0x490,
                              "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\nmethod=%s&valid=%s&uname=%s&mima=***&mima1=***&mima2=***&deviceid=%s&device_name=%s&hardwareid=**********(hwid_len:%d)%s%s%s&customer1=%s, sess_len:%d\n"
                              ,pcStack_12868,param_1 + 0x9c,uStack_12a10,param_1 + 0x837f,
                              sVar5 & 0xffffffff,pcStack_12a30,local_3358,local_348,local_c788,
                              local_ca88,sVar9,local_d398,local_d6a8,local_d9b8,param_1 + 0x4605,
                              sVar10);
        }
      }
      else if (_array_vpn_log_level_ < 2) {
        _Var2 = __OSSwapInt16(*(__uint16_t *)(param_1 + 6));
        if (_Var2 == 0) {
          uStack_12990 = *(uint *)(param_1 + 0x29c);
        }
        else {
          _Var2 = __OSSwapInt16(*(__uint16_t *)(param_1 + 6));
          uStack_12990 = (uint)_Var2;
        }
        sVar5 = _strlen(acStack_105d8);
        if (param_2 == 0) {
          pcStack_129b0 = "";
        }
        else {
          pcStack_129b0 = local_e5d8;
        }
        sVar9 = _strlen(acStack_12728);
        _array_vpn_logprint(1,"aaa.c",0x48b,
                            "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\nUser-Agent: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\nmethod=%s&valid=%s&uname=%s&mima=%s&mima1=%s&mima2=%s&deviceid=%s&device_name=%s&hardwareid=%s%s%s%s&customer1=%s, sess_len:%d\n"
                            ,pcStack_12868,param_1 + 0x9c,uStack_12990,param_1 + 0x837f,
                            sVar5 & 0xffffffff,pcStack_129b0,local_3358,local_348,local_6368,
                            local_9378,local_c388,local_c788,local_ca88,local_cd88,local_d398,
                            local_d6a8,local_d9b8,param_1 + 0x4605,sVar9);
      }
    }
    uStack_1282c = 0;
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_38) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return uStack_1282c;
}

 (GhidraScript)  
===== get_simple_token_values @ 000184b0 ===== (GhidraScript)  
int _get_simple_token_values(char *param_1,code *param_2,undefined8 param_3)

{
  int iVar1;
  int local_248;
  undefined4 local_244;
  char *local_240;
  undefined8 local_238;
  code *local_230;
  char *local_228;
  int local_21c;
  undefined1 local_218 [256];
  undefined1 local_118 [264];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  local_240 = param_1;
  local_238 = param_3;
  local_230 = param_2;
  local_228 = param_1;
  _memset(local_118,0,0x100);
  _memset(local_218,0,0x100);
  local_244 = 0;
  local_248 = 1;
  local_240 = (char *)_get_js_begin(local_240);
  while( true ) {
    if (*local_240 == '\0') {
      local_21c = local_248;
      goto LAB_00018741;
    }
    iVar1 = _get_token_var(&local_240);
    if (iVar1 != 0) break;
    local_21c = _get_token_key(&local_240,local_118,0x100);
    if (local_21c != 0) goto LAB_00018741;
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa_js.c",0x24c,"key: [%s]\n",local_118);
    }
    local_21c = _get_token_char(&local_240,0x3d);
    if ((local_21c != 0) ||
       (local_21c = _get_token_value(&local_240,local_218,&local_244,0x3b,0x100), local_21c != 0))
    goto LAB_00018741;
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa_js.c",0x256,"value: [%s]\n",local_218);
    }
    local_21c = _get_token_char(&local_240,0x3b);
    if ((local_21c != 0) ||
       (local_248 = (*local_230)(local_118,local_218,local_244,local_238), local_21c = local_248,
       local_248 != 0)) goto LAB_00018741;
  }
  if (*local_240 == '\0') {
    local_21c = 0;
  }
  else {
    local_21c = 0;
  }
LAB_00018741:
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_10) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return local_21c;
}

 (GhidraScript)  
===== process_challenge_token @ 00018a30 ===== (GhidraScript)  
undefined8
_process_challenge_token(char *param_1,undefined8 param_2,undefined8 param_3,long param_4)

{
  int iVar1;
  
  iVar1 = _strcasecmp(param_1,"_AN_str_info_chal");
  if (iVar1 == 0) {
    ___strncpy_chk(param_4,param_2,0xff,0x100);
  }
  else {
    iVar1 = _strcasecmp(param_1,"_AN_str_errmsg_chal");
    if (iVar1 == 0) {
      ___strncpy_chk(param_4 + 0x100,param_2,0xff,0xffffffffffffffff);
    }
  }
  return 0;
}

 (GhidraScript)  
===== set_auth_info @ 00039460 ===== (GhidraScript)  
void _set_auth_info(long param_1,long param_2)

{
  int iVar1;
  size_t sVar2;
  char *pcVar3;
  char *pcVar4;
  uint local_20;
  int local_1c;
  
  _memset(&_auth_method,0,0xc12);
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"common.c",&DAT_0000222c,
                        "set_auth_info: start set auth info, method number=%d, method name=%s.\n",
                        *(undefined1 *)(param_2 + 0xf),&UNK_00001300 + param_1);
  }
  if ((param_1 != -0x1602) && (sVar2 = _strlen(&DAT_00001602 + param_1), sVar2 != 0)) {
    ___sprintf_chk(&DAT_0069b603,0,0x201,"%s",&DAT_00001602 + param_1);
  }
  if ((param_1 != -0x2603) && (sVar2 = _strlen(&UNK_00002603 + param_1), sVar2 != 0)) {
    ___sprintf_chk(&DAT_0069b804,0,0x201,"%s",&UNK_00002603 + param_1);
  }
  if ((param_1 != -0x3604) && (sVar2 = _strlen(&UNK_00003604 + param_1), sVar2 != 0)) {
    ___sprintf_chk(&DAT_0069ba05,0,0x201,"%s",&UNK_00003604 + param_1);
  }
  if (*(char *)(param_2 + 0xf) == '\x01') {
    ___sprintf_chk(&_auth_method,0,0x201,"%s",param_2 + 0x416);
    DAT_0069bc06 = *(undefined4 *)(param_2 + 0x818);
  }
  else if (*(char *)(param_2 + 7) == '\0') {
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"common.c",&DAT_00002259,"set_auth_info: rank off.\n");
    }
    for (local_1c = 0; local_1c < (int)(uint)*(byte *)(param_2 + 0xf); local_1c = local_1c + 1) {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"common.c",&DAT_0000225f,
                            "set_auth_info: i=%d, method server=%s, method type=%d.\n",local_1c,
                            param_2 + (long)local_1c * 0x1b3b + 0x416,
                            *(undefined4 *)(param_2 + (long)local_1c * 0x1b3b + 0x818));
      }
      iVar1 = _strncmp((char *)(param_2 + 0x14 + (long)local_1c * 0x1b3b),&UNK_00001300 + param_1,
                       0x201);
      if (iVar1 == 0) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"common.c",&DAT_00002262,
                              "set_auth_info: get auth method info start.\n");
        }
        ___sprintf_chk(&_auth_method,0,0x201,"%s",param_2 + (long)local_1c * 0x1b3b + 0x416);
        DAT_0069bc06 = *(undefined4 *)(param_2 + (long)local_1c * 0x1b3b + 0x818);
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"common.c",&DAT_00002265,"set_auth_info: method step count=%d.\n",
                              *(undefined4 *)(param_2 + (long)local_1c * 0x1b3b + 0x925));
        }
        for (local_20 = 0; local_20 < *(uint *)(param_2 + (long)local_1c * 0x1b3b + 0x925);
            local_20 = local_20 + 1) {
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"common.c",&DAT_0000226a,
                                "set_auth_info: iStep=%d, method server=%s, method type=%d.\n",
                                local_20,param_2 + (long)local_1c * 0x1b3b + 0x929 +
                                         (long)(int)local_20 * 0x40a,
                                *(undefined4 *)
                                 (param_2 + (long)local_1c * 0x1b3b + (long)(int)local_20 * 0x40a +
                                 0xd2b));
          }
          if (local_20 == 0) {
            ___sprintf_chk(&DAT_0069b201,0,0x201,"%s",param_2 + (long)local_1c * 0x1b3b + 0x929);
            DAT_0069bc0a = *(undefined4 *)(param_2 + (long)local_1c * 0x1b3b + 0xd2b);
          }
          if (local_20 == 1) {
            ___sprintf_chk(&DAT_0069b402,0,0x201,"%s",param_2 + (long)local_1c * 0x1b3b + 0xd33);
            DAT_0069bc0e = *(undefined4 *)(&UNK_00001135 + param_2 + (long)local_1c * 0x1b3b);
          }
        }
      }
    }
  }
  else {
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"common.c",&DAT_00002245,"set_auth_info: rank on.\n");
    }
    DAT_0069bc06 = 1;
    ___sprintf_chk(&_auth_method,0,0x201,"%s",param_2 + 0x416);
    if ((param_1 != -0x2a0) && (sVar2 = _strlen((char *)(param_1 + 0x2a0)), sVar2 != 0)) {
      pcVar3 = _strstr((char *)(param_1 + 0x2a0),"=");
      pcVar3 = pcVar3 + 1;
      if (pcVar3 == (char *)0x0) {
        return;
      }
      pcVar4 = _strstr(pcVar3,"+");
      if (pcVar4 == (char *)0x0) {
        return;
      }
      _memset(&_auth_method,0,0x201);
      ___strncpy_chk(&_auth_method,pcVar3,(long)pcVar4 - (long)pcVar3,0x201);
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"common.c",&DAT_00002253,"set_auth_info: rank on, server=%s.\n",
                          &_auth_method);
    }
  }
  return;
}

 (GhidraScript)  
===== handle_atp_packets @ 00060400 ===== (GhidraScript)  
undefined4 _handle_atp_packets(long param_1,long param_2,int param_3)

{
  undefined2 uVar1;
  int iVar2;
  __uint16_t _Var3;
  short sVar4;
  __uint32_t _Var5;
  int iVar6;
  size_t sVar7;
  undefined8 uVar8;
  long lVar9;
  char *pcVar10;
  long local_4048;
  undefined4 local_4030;
  char local_4018 [16392];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  local_4030 = 0;
  iVar6 = *(int *)(param_1 + 0x98);
  local_4048 = 0;
  _memset(local_4018,0,0x4000);
  if (*(char *)(param_2 + 9) == -1) {
    uVar1 = *(undefined2 *)(param_2 + 2);
    _Var3 = __OSSwapInt16(*(__uint16_t *)(param_2 + 0xc));
    *(__uint16_t *)(param_2 + 0xc) = _Var3;
    iVar2 = *(int *)(param_2 + 0x10);
    _Var5 = __OSSwapInt32(*(__uint32_t *)(param_2 + 0x10));
    *(__uint32_t *)(param_2 + 0x10) = _Var5;
    switch(*(undefined2 *)(param_2 + 0xc)) {
    case 1:
      if (_array_vpn_log_level_ < 2) {
        pcVar10 = "TCP";
        if (param_3 == 1) {
          pcVar10 = "Speed";
        }
        _array_vpn_logprint(1,"l3vpn.c",0x45b,
                            "Received keep alive packet from L3 %s Tunnel, send: %d, recv:0, interval:0\n"
                            ,pcVar10,iVar2,0,-iVar2);
      }
      break;
    case 2:
      if (*(int *)(param_2 + 0x10) == 1) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x48a,
                              "ATP_AG_KILL_TUNNEL: user login again, current session will be terminated.\n"
                             );
        }
        *(uint *)(param_1 + 0x8490) = *(uint *)(param_1 + 0x8490) | 0x4000;
        local_4030 = 0x1f;
      }
      else if ((iVar6 == 1) && (*(int *)(param_2 + 0x10) == 2)) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x48e,"ATP_AG_KILL_TUNNEL: session is invalid!\n");
        }
        local_4030 = 7;
      }
      else if ((iVar6 == 2) && (*(int *)(param_2 + 0x10) == 3)) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x491,"ATP_AG_KILL_TUNNEL: session has expired!\n");
        }
        local_4030 = 7;
      }
      else if ((iVar6 == 2) && (*(int *)(param_2 + 0x10) == 8)) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x494,"ATP_AG_KILL_TUNNEL: session logout.\n");
        }
        local_4030 = 6;
      }
      else if ((iVar6 == 2) && (*(int *)(param_2 + 0x10) == 0xf)) {
        iVar6 = _GetWGStatus();
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x498,
                              "ATP_AG_KILL_TUNNEL: wireguard is not available, ag send restart VPN command to client, client wg status: %d\n"
                              ,iVar6);
        }
        if (iVar6 == 10) {
          *(undefined4 *)(param_1 + 0x54) = 0x86;
          _g_wg_running = 2;
        }
      }
      else if (*(int *)(param_2 + 0x10) == 0xe) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x4a0,
                              "ATP_AG_KILL_TUNNEL: the second session with same client id, disconnect VPN.\n"
                             );
        }
        local_4030 = 0x93;
      }
      else {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x4a3,
                              "ATP_AG_KILL_TUNNEL: disconnect VPN, unknown reason %d\n",
                              *(undefined4 *)(param_2 + 0x10));
        }
        local_4030 = 6;
      }
      break;
    default:
      if (_array_vpn_log_level_ < 3) {
        _array_vpn_logprint(2,"l3vpn.c",0x4c2,
                            "received unknown atp control packet, cmd=%d, len:%d, reserved:%d\n",
                            *(undefined2 *)(param_2 + 0xc),uVar1,*(undefined2 *)(param_2 + 0xe));
      }
      break;
    case 4:
      *(short *)(param_1 + 0x10b18) = (short)*(undefined4 *)(param_2 + 0x10);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0x4ac,"speed tunnel port: [%d]\n",
                            *(undefined2 *)(param_1 + 0x10b18));
      }
      _Var3 = __OSSwapInt16(*(__uint16_t *)(param_2 + 2));
      if ((ulong)_Var3 - 0x14 < 0x5dc) {
        sVar4 = _Var3 - 0x14;
      }
      else {
        sVar4 = 0x5dc;
      }
      *(short *)(param_1 + 0x11124) = sVar4;
      ___memset_chk(param_1 + 0x10b48,0,0x5dc,0xffffffffffffffff);
      ___memcpy_chk(param_1 + 0x10b48,param_2 + 0x14,*(undefined2 *)(param_1 + 0x11124),
                    0xffffffffffffffff);
      *(char *)(param_1 + 0x1112c) = (char)*(undefined2 *)(param_2 + 0xe);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0x4b4,"speed tunnel coreid: [%d]\n",
                            *(undefined1 *)(param_1 + 0x1112c));
      }
      if ((*(char *)(param_1 + 0x1112c) == '\0') ||
         (pcVar10 = _strstr((char *)(param_1 + 0x10b48),"DTLS SPEED TUNNEL"), pcVar10 == (char *)0x0
         )) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x4bc,
                              "This is UDP tunnel, start to do start_udp_open_thread\n");
        }
        _start_udp_open_thread(0);
      }
      else {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0x4b7,"This is DTLS tunnel\n");
        }
        _start_udp_open_thread(1);
      }
      break;
    case 5:
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0x4a8,"received switch tunnel response.\n");
      }
      break;
    case 6:
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0x460,"received ATP_VPN_GET_INFO packet\n");
      }
      _Var3 = __OSSwapInt16(*(__uint16_t *)(param_2 + 2));
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0x463,"ATP_VPN_GET_INFO: package len:[%d]\n",_Var3);
      }
      if ((ulong)_Var3 - 0x14 < 0x4000) {
        iVar6 = _Var3 - 0x14;
      }
      else {
        iVar6 = 0x4000;
      }
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0x467,"ATP_VPN_GET_INFO: data len:[%d]\n",iVar6);
      }
      _memset(local_4018,0,0x4000);
      ___memcpy_chk(local_4018,param_2 + 0x14,(long)iVar6,0x4000);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0x46b,"data: [%s]\n",local_4018);
      }
      sVar7 = _strlen(local_4018);
      if (sVar7 != 0) {
        local_4048 = _cJSON_Parse(local_4018);
        if (local_4048 == 0) {
          if (_array_vpn_log_level_ < 4) {
            uVar8 = _cJSON_GetErrorPtr();
            _array_vpn_logprint(3,"l3vpn.c",0x475,
                                "get_vpn_info: failed to parse from g_chMPTokenL3, error: %s\n",
                                uVar8);
          }
        }
        else {
          lVar9 = _cJSON_GetObjectItem(local_4048,"mptoken");
          if (lVar9 == 0) {
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"l3vpn.c",0x484,"can not get mptoken\n");
            }
          }
          else if (*(int *)(lVar9 + 0x28) != 0) {
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"l3vpn.c",0x47d,"Get_MP_Token:%d\n",
                                  *(undefined4 *)(lVar9 + 0x28));
            }
            ___sprintf_chk(&_g_chMPTokenL3,0,0x100,"%d",*(undefined4 *)(lVar9 + 0x28));
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"l3vpn.c",0x47f,"g_chMPTokenL3:%s\n",&_g_chMPTokenL3);
            }
          }
        }
      }
    }
  }
  if (local_4048 != 0) {
    _cJSON_Delete(local_4048);
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 == local_10) {
    return local_4030;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

 (GhidraScript)  
===== write_to_vnic @ 000610d0 ===== (GhidraScript)  
int _write_to_vnic(long param_1,undefined8 param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  int local_c;
  
  if ((*(uint *)(param_1 + 0x5e58) & 0x200) == 0) {
    iVar1 = _write_to_lwip(param_2,param_3);
    local_c = param_3;
    if (iVar1 != 0) {
      if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"l3vpn.c",0x533,"failed to write data to tcp/ip stack!\n");
      }
      local_c = -1;
    }
  }
  else {
    local_c = _xtun_write(*(undefined4 *)(param_1 + 0x130f8),param_2,(long)param_3);
    if (local_c < 1) {
      if (_array_vpn_log_level_ < 4) {
        piVar2 = ___error();
        _array_vpn_logprint(3,"l3vpn.c",0x52b,"write tun dev failed, error %d, len %d",*piVar2,
                            param_3);
      }
      local_c = -1;
    }
  }
  return local_c;
}

 (GhidraScript)  
===== array_vpn_start @ 000699a0 ===== (GhidraScript)  
int _array_vpn_start(undefined8 param_1,undefined4 param_2,long param_3,long param_4,long param_5,
                    long param_6,long param_7,long param_8,long param_9,long param_10,char *param_11
                    ,char *param_12,long param_13,long param_14,undefined8 param_15,uint param_16,
                    long param_17,int param_18,undefined4 param_19,undefined4 param_20,
                    undefined4 param_21,undefined4 param_22,long param_23,uint param_24,
                    undefined8 param_25)

{
  long *plVar1;
  int iVar2;
  size_t sVar3;
  int local_c4;
  int local_8c;
  char local_88 [32];
  char local_68 [48];
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"l3vpn.c",0xea4,"array_vpn_start enter.\n");
  }
  _memset(&_g_l3vpn_memory_info,0,0x200);
  _set_connect_thread_flag("SDKConnectThread2");
  _memset(&_g_aaa_auth_input,0,0x8a0b);
  ___sprintf_chk(&_g_aaa_auth_input,0,0x201,"%s","user_cancel_the_aaa");
  _init_once();
  iVar2 = _get_disable_tls_1_3_flag();
  _g_disable_tls_1_3_flag = (uint)(iVar2 == 1);
  _set_udp_tunnel_running_status(0);
  _SetKeepaliveSettings(1,0,0);
  _SetKeepaliveSettings(2,0,0);
  _SetKeepaliveSettings(3,0,0);
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"l3vpn.c",0xebb,"set udp tunnel status and keepalive settings\n");
  }
  _memset(&_g_skfInfo,0,0x339448);
  _memset(&_g_skf_using,0,0x280);
  iVar2 = _thrd_is_null(DAT_006fdd20);
  if (iVar2 == 0) {
    if (_array_vpn_log_level_ < 4) {
      _array_vpn_logprint(3,"l3vpn.c",0xec0,"vpn thread is running, do nothing\n");
    }
    local_8c = 0x19;
  }
  else {
    _g_l4vpn_is_running = 0;
    if ((param_24 & 0x10000) == 0) {
      if ((param_24 & 0x100000) == 0) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"l3vpn.c",0xed2,"array_vpn_start: this is aaa.\n");
        }
        _memset(&_g_mauth_pin,0,0x100);
      }
      else if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0xecd,"array_vpn_start: this is l3vpn\n");
      }
      _g_l4vpn_is_running = 0;
    }
    else {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0xec6,"array_vpn_start: this is l4vpn\n");
      }
      _g_l4vpn_is_running = 1;
    }
    if (((param_24 & 0x80000000) == 0) &&
       (_memset(&_l3vpn_data,0,0x13118), _array_vpn_log_level_ < 2)) {
      _array_vpn_logprint(1,"l3vpn.c",0xeda,"array_vpn_start: clear l3vpn_data\n");
    }
    _l3vpn_data = 0xffffffff;
    DAT_00708b10 = 0xffffffff;
    DAT_0070b100 = 0xffffffff;
    DAT_0070b104 = 0xffffffff;
    DAT_00703bc2 = 0;
    DAT_00703bc3 = 0;
    DAT_007063fa = 0;
    DAT_0070b11c = 0;
    if (((param_24 & 0x1000000) != 0) && (DAT_0070b11c = 1, _array_vpn_log_level_ < 2)) {
      _array_vpn_logprint(1,"l3vpn.c",0xee8,"array_vpn_start: ipsec_enable=%d\n",1);
    }
    sVar3 = _strlen(&DAT_006f80a4);
    if ((sVar3 == 0) &&
       (___sprintf_chk(&DAT_006f80a4,0,0x100,"%s",&DAT_006f81a4), _array_vpn_log_level_ < 2)) {
      _array_vpn_logprint(1,"l3vpn.c",0xeee,"update l3vpn_data.sess.host to %s using domain\n",
                          &DAT_006f80a4);
    }
    if (param_3 != 0) {
      ___strncpy_chk(&DAT_006f92c8,param_3,0x3f,0x40);
    }
    if (param_4 != 0) {
      ___strncpy_chk(&DAT_006f9308,param_4,0x200,0x201);
    }
    if (param_5 != 0) {
      ___strncpy_chk(&DAT_006f9509,param_5,0x100,0x101);
    }
    if (param_6 != 0) {
      ___strncpy_chk(&DAT_006f960a,param_6,0x1000,&DAT_00001001);
    }
    if (param_7 != 0) {
      ___strncpy_chk(&DAT_006fa60b,param_7,0x1000,&DAT_00001001);
    }
    if (param_8 != 0) {
      ___strncpy_chk(&DAT_006fb60c,param_8,0x1000,&DAT_00001001);
    }
    if (param_13 != 0) {
      ___strncpy_chk(&DAT_006fd30e,param_13,0xff,0x100);
    }
    if (param_14 != 0) {
      ___strncpy_chk(&DAT_006fd40e,param_14,0xff,0x100);
    }
    if (param_17 != 0) {
      ___strncpy_chk(&DAT_00701ac1,param_17,0xff,0x100);
    }
    if (param_10 != 0) {
      ___strncpy_chk(&DAT_006fca0d,param_10,0x3ff,0x400);
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"l3vpn.c",0xefe,"array_vpn_start: valid code=[%s].\n",&DAT_006fca0d);
    }
    if (param_9 != 0) {
      ___strncpy_chk(&DAT_006f82a8,param_9,&DAT_0000101f,&DAT_00001020);
    }
    if (param_23 != 0) {
      ___strncpy_chk(&DAT_00700387,param_23,0xff,0x100);
    }
    if ((param_11 == (char *)0x0) || (sVar3 = _strlen(param_11), sVar3 == 0)) {
      _array_vpn_get_devid(&DAT_006fce0d,0xff);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0xf0a,
                            "array_vpn_start: devid is null, we call array_vpn_get_devid to get the value, which is %s\n"
                            ,&DAT_006fce0d);
      }
    }
    else {
      ___strncpy_chk(&DAT_006fce0d,param_11,0xff,0x100);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0xf05,
                            "array_vpn_start: devid is %s, which is a correct value, using it\n",
                            param_11);
      }
    }
    if ((param_12 == (char *)0x0) || (sVar3 = _strlen(param_12), sVar3 == 0)) {
      _gethostname(&DAT_006fcf0d,0x200);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0xf15,
                            "array_vpn_start: devname is null, we call gethostname to get the value, which is %s\n"
                            ,&DAT_006fcf0d);
      }
      sVar3 = _strlen(&DAT_006fcf0d);
      if (sVar3 == 0) {
        ___strncpy_chk(&DAT_006fcf0d,"ArrayVPNClient",0xe,0x201);
      }
    }
    else {
      sVar3 = _strlen(param_12);
      ___strncpy_chk(&DAT_006fcf0d,param_12,sVar3,0x201);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0xf10,
                            "array_vpn_start: devname is %s, which is a correct value, using it\n",
                            param_12);
      }
    }
    _array_vpn_get_hardwareid(&DAT_006fd20e,0xff);
    if (param_16 != 0) {
      DAT_006fd510 = _calloc((ulong)param_16,1);
      ___memcpy_chk(DAT_006fd510,param_15,param_16,0xffffffffffffffff);
      DAT_006fd518 = param_16;
    }
    DAT_006fdd28 = param_21;
    DAT_006fdd2c = param_22;
    DAT_006fdd1c = 1;
    DAT_006fde68 = param_25;
    DAT_006fde60 = param_24;
    DAT_006f82a4 = param_2;
    ___strncpy_chk(&DAT_006fdd38,"default",7,0x100);
    if (param_18 != 0) {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0xf34,"array_vpn_start: client tunnel type=%d.\n",param_18);
      }
      DAT_00708b14 = param_18;
      DAT_00708b18 = param_19;
      DAT_00709130 = param_20;
    }
    sVar3 = _strlen(&DAT_006fce0d);
    if (sVar3 == 0) {
      _memset(local_38,0,0x25);
      _get_random_str(local_38,0x25);
      sVar3 = _strlen(local_38);
      if (sVar3 == 0) {
        ___strncpy_chk(&DAT_006fce0d,"BFBFFBFB000101A1A1D4589C69D897A6D92A",0x24,0x100);
      }
      else {
        sVar3 = _strlen(local_38);
        ___strncpy_chk(&DAT_006fce0d,local_38,sVar3,0x100);
      }
    }
    sVar3 = _strlen(&DAT_006fde38);
    if ((sVar3 == 0) && (_generate_uuid(&DAT_006fde38), _array_vpn_log_level_ < 2)) {
      _array_vpn_logprint(1,"l3vpn.c",0xf4b,
                          "array_vpn_start: generate clientid (uuid), which is %s\n",&DAT_006fde38);
    }
    sVar3 = _strlen(&DAT_006fde38);
    if (sVar3 == 0) {
      _memset(local_68,0,0x25);
      _get_random_str(local_68,0x25);
      sVar3 = _strlen(local_68);
      if (sVar3 == 0) {
        ___strncpy_chk(&DAT_006fde38,"BFBFFBFB000101A1A1D4589C69D897A6D92A",0x24,0x25);
      }
      else {
        sVar3 = _strlen(local_68);
        ___strncpy_chk(&DAT_006fde38,local_68,sVar3,0x25);
      }
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"l3vpn.c",0xf57,
                            "array_vpn_start: generate clientid (random), which is %s\n",local_68);
      }
    }
    sVar3 = _strlen(&DAT_006fcf0d);
    if (sVar3 == 0) {
      _memset(local_88,0,0x14);
      _get_random_str(local_88,0x14);
      sVar3 = _strlen(local_88);
      if (sVar3 == 0) {
        ___strncpy_chk(&DAT_006fcf0d,"BFBFFBFB000101A1ARM",0x13,0x201);
      }
      else {
        sVar3 = _strlen(local_88);
        ___strncpy_chk(&DAT_006fcf0d,local_88,sVar3,0x201);
      }
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"l3vpn.c",0xf68,"array_vpn_start: genereate devname: %s\n",&DAT_006fcf0d
                         );
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"l3vpn.c",0xf69,"array_vpn_start: genereate clientid: %s\n",
                          &DAT_006fde38);
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"l3vpn.c",0xf6a,"array_vpn_start: genereate devid: %s\n",&DAT_006fce0d);
    }
    _mtx_lock(&_ssl_tunnel_write_lock);
    while (plVar1 = _lwip_to_ssl_data_list_head, _lwip_to_ssl_data_list_head != (long *)0x0) {
      if (*_lwip_to_ssl_data_list_head == 0) {
        DAT_0070b128 = (undefined8 *)_lwip_to_ssl_data_list_head[1];
      }
      else {
        *(long *)(*_lwip_to_ssl_data_list_head + 8) = _lwip_to_ssl_data_list_head[1];
      }
      *(long *)plVar1[1] = *plVar1;
      _free(plVar1);
    }
    _lwip_to_ssl_data_list_head = (long *)0x0;
    DAT_0070b128 = &_lwip_to_ssl_data_list_head;
    _mtx_unlock(&_ssl_tunnel_write_lock);
    local_c4 = _thrd_create(&DAT_006fdd20,_l3vpn_tunnel_thread);
    if (local_c4 != 0) {
      if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"l3vpn.c",0xf78,"create vpn thread failed.\n");
      }
      local_c4 = 0x1c;
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"l3vpn.c",0xf7c,"array_vpn_start end\n");
    }
    local_8c = local_c4;
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 == local_10) {
    return local_8c;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

 (GhidraScript)  
