===== update_aaa_method @ 000072b0 ===== (GhidraScript)  
undefined4 _update_aaa_method(undefined8 param_1,undefined8 param_2)

{
  undefined4 uVar1;
  
  uVar1 = _update_aaa_method_info(param_1,param_2);
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"aaa.c",0x1b0,"update_aaa_method finished, new aaa method num %d\n",uVar1)
    ;
  }
  return uVar1;
}

 (GhidraScript)  
===== get_aaa_method @ 00007310 ===== (GhidraScript)  
int _get_aaa_method(long param_1,undefined4 *param_2)

{
  __uint16_t _Var1;
  int iVar2;
  undefined4 uVar3;
  size_t sVar4;
  int *piVar5;
  char *pcVar6;
  size_t sVar7;
  long lVar8;
  undefined8 in_stack_fffffffffffde4f8;
  undefined1 *puVar9;
  undefined8 in_stack_fffffffffffde510;
  undefined4 uVar11;
  undefined8 uVar10;
  uint uStack_21aa0;
  undefined4 uStack_21a6c;
  int iStack_21a68;
  int iStack_21a64;
  char *pcStack_21a60;
  undefined4 uStack_21a54;
  undefined4 *puStack_21a50;
  long lStack_21a48;
  int iStack_21a3c;
  char acStack_21a38 [65536];
  char acStack_11a38 [65536];
  char local_1a38 [256];
  undefined1 local_1938 [256];
  undefined1 local_1838 [768];
  undefined1 local_1538 [256];
  undefined1 local_1438 [5128];
  long local_30;
  
  uVar3 = (undefined4)((ulong)in_stack_fffffffffffde4f8 >> 0x20);
  uVar11 = (undefined4)((ulong)in_stack_fffffffffffde510 >> 0x20);
  local_30 = *(long *)PTR____stack_chk_guard_002e4060;
  puStack_21a50 = param_2;
  lStack_21a48 = param_1;
  _memset(local_1438,0,0x1400);
  uStack_21a54 = 0;
  pcStack_21a60 = (char *)0x0;
  _memset(local_1538,0,0x100);
  _memset(local_1838,0,0x2fe);
  _memset(local_1938,0,0x100);
  sVar4 = _strlen(&UNK_000012c0 + lStack_21a48);
  if ((sVar4 == 0) ||
     (iStack_21a64 = _get_alias_site_cookie(lStack_21a48,lStack_21a48 + 0x2a0,&DAT_00001020),
     iStack_21a64 == 0)) {
    _memset(local_1a38,0,0x100);
    _array_get_spa_sess(local_1a38,0x100);
    _GetZeroTrustInfo("csip",local_1538,0x100);
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x1cd,"get local ip finished[%s]",local_1538);
    }
    _url_escape(lStack_21a48 + 0x4e05,local_1838);
    ___strncpy_chk(local_1938,local_1838,0xff,0x100);
    iStack_21a68 = _IsDisabledZeroTrust();
    iVar2 = _is_ipv6_host(lStack_21a48 + 0x9c);
    if (iVar2 == 0) {
      if (iStack_21a68 == 1) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x1e0,"This is no zert trust mode.\n");
        }
        lVar8 = lStack_21a48 + 0x2a0;
        ___sprintf_chk(local_1438,0,&DAT_00001400,
                       "GET /prx/000/http/localhost/%s HTTP/1.1\r\nHost: %s:%u\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: %s\r\n\r\n"
                       ,"an_login.js",lStack_21a48 + 0x9c,
                       CONCAT44(uVar3,*(undefined4 *)(lStack_21a48 + 0x29c)),lVar8,local_1a38,
                       "SSPVPN");
        uVar3 = (undefined4)((ulong)lVar8 >> 0x20);
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x1e2,
                              "get aaa method: req:GET %s/an_login.js HTTP/1.1\r\nHost: %s:%u\r\nspa-session=***appid: SSPVPN\r\n"
                              ,"/prx/000/http/localhost",lStack_21a48 + 0x9c,
                              *(undefined4 *)(lStack_21a48 + 0x29c));
        }
      }
      else {
        uVar3 = _get_current_dev_type();
        puVar9 = local_1938;
        uVar10 = CONCAT44(uVar11,*(undefined4 *)(lStack_21a48 + 0x29c));
        ___sprintf_chk(local_1438,0,&DAT_00001400,
                       "GET /prx/000/http/localhost/%s?devtype=%d&localip=%s&deviceid=%s&end=1 HTTP/1.1\r\nHost: %s:%u\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: %s\r\n\r\n"
                       ,"an_login.js",uVar3,local_1538,puVar9,lStack_21a48 + 0x9c,uVar10,
                       lStack_21a48 + 0x2a0,local_1a38,"SSPVPN");
        uVar3 = (undefined4)((ulong)puVar9 >> 0x20);
        uVar11 = (undefined4)((ulong)uVar10 >> 0x20);
        if (_array_vpn_log_level_ < 2) {
          uVar3 = _get_current_dev_type();
          puVar9 = local_1938;
          _array_vpn_logprint(1,"aaa.c",0x1e6,
                              "get aaa method: req:GET %s/an_login.js?devtype=%d&localip=%s&deviceid=%s&end=1 HTTP/1.1\r\nHost: %s:%u\r\nspa-session=***appid: SSPVPN\r\n"
                              ,"/prx/000/http/localhost",uVar3,local_1538,puVar9,lStack_21a48 + 0x9c
                              ,CONCAT44(uVar11,*(undefined4 *)(lStack_21a48 + 0x29c)));
          uVar3 = (undefined4)((ulong)puVar9 >> 0x20);
        }
      }
    }
    else if (iStack_21a68 == 1) {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x1d4,"This is no zert trust mode.\n");
      }
      lVar8 = lStack_21a48 + 0x2a0;
      ___sprintf_chk(local_1438,0,&DAT_00001400,
                     "GET /prx/000/http/localhost/%s HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: %s\r\n\r\n"
                     ,"an_login.js",lStack_21a48 + 0x9c,
                     CONCAT44(uVar3,*(undefined4 *)(lStack_21a48 + 0x29c)),lVar8,local_1a38,"SSPVPN"
                    );
      uVar3 = (undefined4)((ulong)lVar8 >> 0x20);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x1d6,
                            "get aaa method: req:GET %s/an_login.js HTTP/1.1\r\nHost: [%s]:%u\r\nspa-session=***appid: SSPVPN\r\n"
                            ,"/prx/000/http/localhost",lStack_21a48 + 0x9c,
                            *(undefined4 *)(lStack_21a48 + 0x29c));
      }
    }
    else {
      uVar3 = _get_current_dev_type();
      puVar9 = local_1938;
      uVar10 = CONCAT44(uVar11,*(undefined4 *)(lStack_21a48 + 0x29c));
      ___sprintf_chk(local_1438,0,&DAT_00001400,
                     "GET /prx/000/http/localhost/%s?devtype=%d&localip=%s&deviceid=%s&end=1 HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: %s\r\n\r\n"
                     ,"an_login.js",uVar3,local_1538,puVar9,lStack_21a48 + 0x9c,uVar10,
                     lStack_21a48 + 0x2a0,local_1a38,"SSPVPN");
      uVar3 = (undefined4)((ulong)puVar9 >> 0x20);
      uVar11 = (undefined4)((ulong)uVar10 >> 0x20);
      if (_array_vpn_log_level_ < 2) {
        uVar3 = _get_current_dev_type();
        puVar9 = local_1938;
        _array_vpn_logprint(1,"aaa.c",0x1da,
                            "get aaa method: req:GET %s/an_login.js?devtype=%d&localip=%s&deviceid=%s&end=1 HTTP/1.1\r\nHost: [%s]:%u\r\nspa-session=***appid: SSPVPN\r\n"
                            ,"/prx/000/http/localhost",uVar3,local_1538,puVar9,lStack_21a48 + 0x9c,
                            CONCAT44(uVar11,*(undefined4 *)(lStack_21a48 + 0x29c)));
        uVar3 = (undefined4)((ulong)puVar9 >> 0x20);
      }
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x1ea,"get aaa method: mauth_username:%s.\n",
                          lStack_21a48 + 0xf5f4);
    }
    sVar4 = _strlen((char *)(lStack_21a48 + 0xf5f4));
    if (sVar4 != 0) {
      _memset(acStack_11a38,0,0x10000);
      pcStack_21a60 = _malloc(0x10000);
      iStack_21a64 = _mauth_download(lStack_21a48 + 0x9c,*(undefined4 *)(lStack_21a48 + 0x29c),
                                     local_1438,"sm2",lStack_21a48 + 0xf7f8,acStack_11a38,0x10000);
      pcVar6 = pcStack_21a60;
      if (iStack_21a64 == 0) {
        sVar4 = _strlen(acStack_11a38);
        ___memcpy_chk(pcVar6,acStack_11a38,sVar4,0xffffffffffffffff);
      }
      else {
        _mauth_free(0);
        ___memset_chk(lStack_21a48 + 0xf5f4,0,0x100,0xffffffffffffffff);
      }
    }
    sVar4 = _strlen((char *)(lStack_21a48 + 0xf5f4));
    if (sVar4 == 0) {
      iStack_21a64 = _ssl_get_page_auto_malloc(lStack_21a48,local_1438,&pcStack_21a60,&uStack_21a54)
      ;
    }
    _InitZeroTrustResult();
    if (iStack_21a64 == 0) {
      if ((_g_printlogtraffic == 0) &&
         (pcVar6 = _strstr(pcStack_21a60,"var"), pcVar6 != (char *)0x0)) {
        if (_array_vpn_log_level_ < 2) {
          pcVar6 = _strstr(pcStack_21a60,"var");
          _array_vpn_logprint(1,"aaa.c",0x20b,"get an_login.js, response:\n%s\n",pcVar6);
        }
      }
      else if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x207,"get an_login.js, response:\n%s\n",pcStack_21a60);
      }
      iStack_21a64 = _GetCheckPolicyInfo(pcStack_21a60);
      iVar2 = _array_vpn_is_zero_trust();
      if (iVar2 == 1) {
        uStack_21a6c = 0x101f;
        iVar2 = _GetUnauthSession(pcStack_21a60,lStack_21a48 + 0x2a0,&uStack_21a6c);
        if (iVar2 == 0) {
          if (_g_printlogtraffic == 0) {
            if (_array_vpn_log_level_ < 2) {
              sVar4 = _strlen((char *)(lStack_21a48 + 0x2a0));
              _array_vpn_logprint(1,"aaa.c",0x21d,"get an_login.js session len=%d.\n",sVar4);
            }
          }
          else if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"aaa.c",0x219,"get an_login.js session=%s.\n",lStack_21a48 + 0x2a0
                               );
          }
        }
        else if (_array_vpn_log_level_ < 4) {
          _array_vpn_logprint(3,"aaa.c",0x214,"get an_login.js session failed.\n");
        }
        iStack_21a64 = _vpncallback(lStack_21a48,0x2e,0,0,0,0,0);
        _memset(local_1438,0,0x1400);
        iVar2 = _is_ipv6_host(lStack_21a48 + 0x9c);
        if (iVar2 == 0) {
          ___sprintf_chk(local_1438,0,&DAT_00001400,
                         "GET /prx/000/http/localhost/%s?%s HTTP/1.1\r\nHost: %s:%u\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: %s\r\n\r\n"
                         ,"an_login.js",&_g_zt_result,lStack_21a48 + 0x9c,
                         CONCAT44(uVar3,*(undefined4 *)(lStack_21a48 + 0x29c)),lStack_21a48 + 0x2a0,
                         local_1a38,"SSPVPN");
        }
        else {
          ___sprintf_chk(local_1438,0,&DAT_00001400,
                         "GET /prx/000/http/localhost/%s?%s HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: %s\r\n\r\n"
                         ,"an_login.js",&_g_zt_result,lStack_21a48 + 0x9c,
                         CONCAT44(uVar3,*(undefined4 *)(lStack_21a48 + 0x29c)),lStack_21a48 + 0x2a0,
                         local_1a38,"SSPVPN");
        }
        if (_g_printlogtraffic == 0) {
          if (_array_vpn_log_level_ < 2) {
            lVar8 = lStack_21a48 + 0x9c;
            _Var1 = __OSSwapInt16(*(__uint16_t *)(lStack_21a48 + 6));
            if (_Var1 == 0) {
              uStack_21aa0 = *(uint *)(lStack_21a48 + 0x29c);
            }
            else {
              _Var1 = __OSSwapInt16(*(__uint16_t *)(lStack_21a48 + 6));
              uStack_21aa0 = (uint)_Var1;
            }
            sVar4 = _strlen((char *)(lStack_21a48 + 0x2a0));
            sVar7 = _strlen(local_1a38);
            _array_vpn_logprint(1,"aaa.c",0x23f,
                                "get aaa method: req=GET %s/an_login.js?%s HTTP/1.1\r\nHost: %s:%u\r\nappid: SSPVPN, cookie len:%d, spa_sess len:%d\r\n"
                                ,"/prx/000/http/localhost",&_g_zt_result,lVar8,uStack_21aa0,sVar4,
                                sVar7);
          }
        }
        else if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x23a,"get aaa method: req=%s.\n",local_1438);
        }
        sVar4 = _strlen((char *)(lStack_21a48 + 0xf5f4));
        if (sVar4 != 0) {
          _memset(acStack_21a38,0,0x10000);
          pcStack_21a60 = _malloc(0x10000);
          iStack_21a64 = _mauth_download(lStack_21a48 + 0x9c,*(undefined4 *)(lStack_21a48 + 0x29c),
                                         local_1438,"sm2",lStack_21a48 + 0xf7f8,acStack_21a38,
                                         0x10000);
          pcVar6 = pcStack_21a60;
          if (iStack_21a64 == 0) {
            sVar4 = _strlen(acStack_21a38);
            ___memcpy_chk(pcVar6,acStack_21a38,sVar4,0xffffffffffffffff);
          }
          else {
            _mauth_free(0);
            ___memset_chk(lStack_21a48 + 0xf5f4,0,0x100,0xffffffffffffffff);
          }
        }
        sVar4 = _strlen((char *)(lStack_21a48 + 0xf5f4));
        if (sVar4 == 0) {
          iStack_21a64 = _ssl_get_page_auto_malloc
                                   (lStack_21a48,local_1438,&pcStack_21a60,&uStack_21a54);
        }
        if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
          _array_vpn_logprint(1,"aaa.c",0x259,"get aaa method: resp, ret:%d, buf=%s.\n",iStack_21a64
                              ,pcStack_21a60);
        }
      }
      else {
        iStack_21a64 = _check_client_cert_auth_result(pcStack_21a60);
      }
    }
    if (iStack_21a64 == 0xc) {
      *puStack_21a50 = 1;
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x265,"server is SPX device\n");
      }
      iStack_21a64 = 0;
    }
    else if (iStack_21a64 == 0) {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x270,"start to get_aaa_method_info\n");
      }
      iVar2 = _get_aaa_method_info(pcStack_21a60,puStack_21a50);
      if (iVar2 != 0) {
        if (_array_vpn_log_level_ < 4) {
          _array_vpn_logprint(3,"aaa.c",0x272,"get_aaa_method: failed to parse login page\n");
        }
        iStack_21a64 = 0x26;
      }
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x275,
                            "get_aaa_method_info finished, server is AG_VPN_DEVICE\n");
      }
      *puStack_21a50 = 2;
    }
    else {
      piVar5 = ___error();
      if (*piVar5 == 4) {
        *(undefined4 *)(lStack_21a48 + 0x54) = 0x29;
        iStack_21a64 = 0x29;
      }
    }
    if (pcStack_21a60 != (char *)0x0) {
      _free(pcStack_21a60);
      pcStack_21a60 = (char *)0x0;
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x27f,"get_aaa_method finished\n");
    }
  }
  else {
    piVar5 = ___error();
    if (*piVar5 == 4) {
      *(undefined4 *)(lStack_21a48 + 0x54) = 0x29;
      iStack_21a64 = 0x29;
    }
    if (_array_vpn_log_level_ < 3) {
      _array_vpn_logprint(2,"aaa.c",0x1c5,"get alias site cookie failed, error %d",iStack_21a64);
    }
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_30) {
    iStack_21a3c = iStack_21a64;
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return iStack_21a64;
}

 (GhidraScript)  
===== array_vpn_set_authinfo @ 0000b3e0 ===== (GhidraScript)  
undefined8 _array_vpn_set_authinfo(void *param_1,int param_2)

{
  size_t sVar1;
  
  if (param_2 == 1) {
    if (_array_vpn_log_level_ < 2) {
      sVar1 = _strlen((char *)((long)param_1 + 0x302));
      _array_vpn_logprint(1,"aaa.c",0xa33,
                          "array_vpn_set_authinfo: method: %s, user:%s, *** len is %d, phone number:%s\n"
                          ,param_1,(long)param_1 + 0x201,sVar1,(long)param_1 + 0x5a08);
    }
    _memcpy(&_g_aaa_auth_input,param_1,0x8a0b);
  }
  return 1;
}

 (GhidraScript)  
===== login_ag @ 0000c140 ===== (GhidraScript)  
int _login_ag(long param_1,long param_2,undefined4 param_3,int *param_4)

{
  size_t sVar1;
  long lVar2;
  undefined4 local_8a9c;
  undefined4 local_8a98 [2];
  void *local_8a90;
  long local_8a70;
  int local_8a4c;
  int *local_8a48;
  undefined4 local_8a3c;
  long local_8a38;
  long local_8a30;
  int local_8a24;
  undefined1 local_8a20 [35344];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  local_8a48 = param_4;
  local_8a3c = param_3;
  local_8a38 = param_2;
  local_8a30 = param_1;
  _memset(local_8a98,0,0x48);
  local_8a98[0] = local_8a3c;
  local_8a70 = local_8a38;
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"aaa.c",0xb76,"Login to AG VPN server.\n");
  }
  _g_print_login_loop_log = 0;
LAB_0000c1de:
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"aaa.c",0xb80,"login_ag: process_url -> %d\n",local_8a98[0]);
  }
  switch(local_8a98[0]) {
  case 1:
    goto LAB_0000c24f;
  case 2:
    if (local_8a90 != (void *)0x0) {
      _free(local_8a90);
    }
    local_8a90 = (void *)0x0;
    local_8a4c = _do_devid_register(local_8a30);
    if (local_8a4c != 0) goto LAB_0000c637;
    local_8a4c = 0;
    goto LAB_0000c1de;
  case 3:
  case 4:
    if (local_8a90 == (void *)0x0) {
      if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"aaa.c",0xb9a,"login to ag, response is empty.\n");
      }
      local_8a4c = 1;
      goto LAB_0000c637;
    }
    if ((*(uint *)(local_8a30 + 0x5e58) & 0x800) == 0) {
      _do_after_session_create(local_8a30);
      if (local_8a90 != (void *)0x0) {
        _free(local_8a90);
      }
      local_8a90 = (void *)0x0;
    }
    break;
  case 5:
  case 6:
    _do_after_session_create(local_8a30,local_8a98);
    if (local_8a90 != (void *)0x0) {
      _free(local_8a90);
    }
    local_8a90 = (void *)0x0;
    local_8a4c = _do_change_password(local_8a30);
    if (local_8a4c != 0) goto LAB_0000c637;
    if ((*(uint *)(local_8a30 + 0x5e58) & 0x800) == 0) {
      local_8a4c = 0;
      goto LAB_0000c1de;
    }
    break;
  case 7:
    _do_after_session_create(local_8a30,local_8a98);
    if (local_8a90 != (void *)0x0) {
      _free(local_8a90);
    }
    local_8a90 = (void *)0x0;
    local_8a4c = _do_smx(local_8a30);
    if (local_8a4c != 0) goto LAB_0000c637;
    local_8a4c = 0;
    goto LAB_0000c1de;
  case 8:
    _do_after_session_create(local_8a30,local_8a98);
    if (local_8a90 != (void *)0x0) {
      _free(local_8a90);
    }
    local_8a90 = (void *)0x0;
    local_8a4c = _do_challenge(local_8a30,local_8a98,local_8a48);
    if (local_8a4c != 0) goto LAB_0000c637;
    local_8a4c = 0;
    goto LAB_0000c1de;
  case 9:
    _do_after_session_create(local_8a30,local_8a98);
    if (local_8a90 != (void *)0x0) {
      _free(local_8a90);
    }
    local_8a90 = (void *)0x0;
    local_8a4c = _do_sms(local_8a30);
    if (local_8a4c != 0) goto LAB_0000c637;
    local_8a4c = 0;
    goto LAB_0000c1de;
  case 10:
    local_8a4c = 0x8b;
    goto LAB_0000c637;
  default:
    local_8a4c = 0x25;
    goto LAB_0000c637;
  }
  local_8a4c = 0;
  goto LAB_0000c637;
LAB_0000c24f:
  if (local_8a90 != (void *)0x0) {
    _free(local_8a90);
  }
  local_8a90 = (void *)0x0;
  local_8a4c = _do_normal_login(local_8a30,local_8a98,local_8a48);
  if (local_8a48 == (int *)0x0) {
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0xb8e,"do_normal_login finished, ret:%d\n",local_8a4c);
    }
  }
  else if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"aaa.c",0xb8a,"do_normal_login finished, ret:%d, aaa_method_num:%d\n",
                        local_8a4c,*local_8a48);
  }
  if (local_8a4c != 0) {
LAB_0000c637:
    if (local_8a90 != (void *)0x0) {
      if (local_8a90 != (void *)0x0) {
        _free(local_8a90);
      }
      local_8a90 = (void *)0x0;
    }
    _mauth_free(0);
    _memset(&_g_acs_token,0,0x100);
    if (local_8a38 == 0) {
      if (local_8a4c == 0x90) {
        local_8a24 = local_8a4c;
      }
      else {
        local_8a24 = 0;
      }
    }
    else {
      if ((local_8a38 != 0) && (sVar1 = _strlen((char *)(local_8a38 + 0x118e3)), sVar1 != 0)) {
        lVar2 = local_8a38 + 0x118e3;
        sVar1 = _strlen((char *)(local_8a38 + 0x118e3));
        ___memcpy_chk(&_g_acs_token,lVar2,sVar1,0x100);
      }
      if (local_8a48 == (int *)0x0) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0xbf9,"aaa_method_num is NULL\n");
        }
      }
      else if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0xbfd,"aaa_method_num is not NULL\n");
      }
      if (local_8a38 != 0) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0xc02,
                              "login_ag finished, ret:%d, acs_token:%s, new_token:%s\n",local_8a4c,
                              local_8a38 + 0x118e3,&_g_acs_token);
        }
        _save_netauth_token(local_8a38 + 0x118e3);
        if (((local_8a4c == 0x352) || (local_8a48 == (int *)0x0)) || (*local_8a48 == 0)) {
          local_8a9c = 0x8a0b;
          ___memset_chk(local_8a20,0,0x8a0b,0x8a0b);
          *(undefined4 *)(local_8a70 + 0x10) = 0x352;
          if (local_8a4c != 0x25) {
            local_8a4c = 0;
          }
          _vpncallback(local_8a30,0xd,local_8a4c,local_8a70,0x163ea,local_8a20,&local_8a9c);
          local_8a4c = 0x352;
        }
      }
      local_8a24 = local_8a4c;
    }
    if (*(long *)PTR____stack_chk_guard_002e4060 != local_10) {
                    /* WARNING: Subroutine does not return */
      ___stack_chk_fail();
    }
    return local_8a24;
  }
  goto LAB_0000c1de;
}

 (GhidraScript)  
===== logout_vpn_server @ 00011ac0 ===== (GhidraScript)  
undefined4 _logout_vpn_server(long param_1)

{
  __uint16_t _Var1;
  int iVar2;
  size_t sVar3;
  long lVar4;
  uint local_360;
  uint local_348;
  undefined4 local_334;
  void *local_330;
  long local_328;
  undefined4 local_31c;
  undefined1 local_318 [256];
  undefined1 local_218 [520];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  local_330 = (void *)0x0;
  local_334 = 0;
  local_328 = param_1;
  if (_array_vpn_log_level_ < 2) {
    sVar3 = _strlen((char *)(param_1 + 0x2a0));
    _array_vpn_logprint(1,"aaa.c",0xc20,"logout vpn server begin: sess_len:%d\n",sVar3);
  }
  iVar2 = _ssl_connect_try_all_methods(local_328);
  if (iVar2 == 0) {
    _memset(local_318,0,0x100);
    _array_get_spa_sess(local_318,0x100);
    sVar3 = _strlen((char *)(local_328 + 0x19c));
    if (sVar3 == 0) {
      iVar2 = _is_ipv6_host(local_328 + 0x9c);
      if (iVar2 == 0) {
        ___sprintf_chk(local_218,0,0x200,
                       "GET /prx/000/http/localhost/logout HTTP/1.1\r\nHost: %s:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nappid: %s\r\n\r\n"
                       ,local_328 + 0x9c,*(undefined4 *)(local_328 + 0x29c),local_318,
                       local_328 + 0x2a0,"SSPVPN");
      }
      else {
        ___sprintf_chk(local_218,0,0x200,
                       "GET /prx/000/http/localhost/logout HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nappid: %s\r\n\r\n"
                       ,local_328 + 0x9c,*(undefined4 *)(local_328 + 0x29c),local_318,
                       local_328 + 0x2a0,"SSPVPN");
      }
    }
    else {
      iVar2 = _is_ipv6_host(local_328 + 0x19c);
      if (iVar2 == 0) {
        ___sprintf_chk(local_218,0,0x200,
                       "GET /prx/000/http/localhost/logout HTTP/1.1\r\nHost: %s:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nappid: %s\r\n\r\n"
                       ,local_328 + 0x19c,*(undefined4 *)(local_328 + 0x29c),local_318,
                       local_328 + 0x2a0,"SSPVPN");
      }
      else {
        ___sprintf_chk(local_218,0,0x200,
                       "GET /prx/000/http/localhost/logout HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nappid: %s\r\n\r\n"
                       ,local_328 + 0x19c,*(undefined4 *)(local_328 + 0x29c),local_318,
                       local_328 + 0x2a0,"SSPVPN");
      }
    }
    if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
      _array_vpn_logprint(1,"aaa.c",0xc43,"logout_vpn_server: logout request=%s.\n",local_218);
    }
    sVar3 = _strlen((char *)(local_328 + 0x19c));
    if (sVar3 == 0) {
      if (_array_vpn_log_level_ < 2) {
        lVar4 = local_328 + 0x9c;
        _Var1 = __OSSwapInt16(*(__uint16_t *)(local_328 + 6));
        if (_Var1 == 0) {
          local_360 = *(uint *)(local_328 + 0x29c);
        }
        else {
          _Var1 = __OSSwapInt16(*(__uint16_t *)(local_328 + 6));
          local_360 = (uint)_Var1;
        }
        _array_vpn_logprint(1,"aaa.c",0xc4c,
                            "GET /prx/000/http/localhost/logout HTTP / 1.1\r\nHost: %s : %u\r\nCookie: ANStandalone = true; ANSession** *= ***+*** appid: SSPVPN"
                            ,lVar4,local_360);
      }
    }
    else if (_array_vpn_log_level_ < 2) {
      lVar4 = local_328 + 0x19c;
      _Var1 = __OSSwapInt16(*(__uint16_t *)(local_328 + 6));
      if (_Var1 == 0) {
        local_348 = *(uint *)(local_328 + 0x29c);
      }
      else {
        _Var1 = __OSSwapInt16(*(__uint16_t *)(local_328 + 6));
        local_348 = (uint)_Var1;
      }
      _array_vpn_logprint(1,"aaa.c",0xc48,
                          "GET /prx/000/http/localhost/logout HTTP / 1.1\r\nHost: %s : %u\r\nCookie: ANStandalone = true; ANSession** *= ***+*** appid: SSPVPN"
                          ,lVar4,local_348);
    }
    iVar2 = _ssl_get_page_auto_malloc(local_328,local_218,&local_330,&local_334);
    if (iVar2 == 0) {
      if (*(int *)(local_328 + 0x98) == 1) {
        if (local_330 != (void *)0x0) {
          _free(local_330);
        }
        local_330 = (void *)0x0;
        iVar2 = _ssl_get_page_auto_malloc(local_328,local_218,&local_330,&local_334);
        if ((iVar2 != 0) && (_array_vpn_log_level_ < 2)) {
          _array_vpn_logprint(1,"aaa.c",0xc5e,"logout again for spx failed, error %d\n",iVar2);
        }
      }
    }
    else if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0xc52,"logout failed, error %d\n",iVar2);
    }
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0xc64,"logout successfully\n");
    }
    if (local_330 != (void *)0x0) {
      _free(local_330);
    }
    local_330 = (void *)0x0;
    local_31c = 0;
  }
  else {
    if (_array_vpn_log_level_ < 3) {
      _array_vpn_logprint(2,"aaa.c",0xc23,"connect to VPN server failed, error: %d\n",iVar2);
    }
    *(int *)(local_328 + 0x54) = iVar2;
    local_31c = *(undefined4 *)(local_328 + 0x54);
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_10) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return local_31c;
}

 (GhidraScript)  
===== do_after_login @ 000128c0 ===== (GhidraScript)  
undefined4 _do_after_login(long param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  char *pcVar2;
  size_t sVar3;
  undefined4 local_7c;
  undefined8 local_78;
  undefined8 local_70;
  long local_68;
  undefined4 local_5c;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  local_78 = param_3;
  local_70 = param_2;
  local_68 = param_1;
  _memset(local_58,0,0x40);
  local_7c = 0;
  iVar1 = _is_http_redirect(local_78);
  if (iVar1 == 0) {
    if (_array_vpn_log_level_ < 4) {
      _array_vpn_logprint(3,"aaa.c",0xcbc,"uncorrect response message\n");
    }
    local_5c = 0x25;
  }
  else {
    local_7c = 0x3f;
    iVar1 = _get_page_location(local_78,local_58,&local_7c);
    if (iVar1 == 0) {
      pcVar2 = _strstr(local_58,"/prx/000/http/localhost/welcome");
      if (pcVar2 == (char *)0x0) {
        pcVar2 = _strstr(local_58,"/prx/000/http/localhost/welcome");
        if (pcVar2 == (char *)0x0) {
          if (_array_vpn_log_level_ < 4) {
            _array_vpn_logprint(3,"aaa.c",0xcd3,"location url is not welcome\n");
          }
          local_5c = 0x25;
          goto LAB_00012af9;
        }
      }
      _get_session_cookie(local_78,local_68 + 0x2a0,&DAT_0000101f);
      _get_roles_from_cookie(local_78,local_68 + 0x5514,0x7ff);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0xcc9,"do_after_login: username: %s\n",
                            &UNK_00001501 + local_68);
      }
      sVar3 = _strlen(&UNK_00001501 + local_68);
      if (sVar3 == 0) {
        _get_username_from_cookie(local_78,&UNK_00001501 + local_68,0x100);
      }
      _set_ad_pass_index(local_68,local_70);
      _get_session_id_from_cookie(local_78,local_68 + 0x7f6f,0x10);
      _update_session_nav(local_68);
      local_5c = 0;
    }
    else {
      if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"aaa.c",0xcc2,"get location failed\n");
      }
      local_5c = 0x14;
    }
  }
LAB_00012af9:
  if (*(long *)PTR____stack_chk_guard_002e4060 == local_10) {
    return local_5c;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

 (GhidraScript)  
===== get_challenge_info @ 000189e0 ===== (GhidraScript)  
void _get_challenge_info(undefined8 param_1,undefined8 param_2)

{
  ___memset_chk(param_2,0,0x200,0xffffffffffffffff);
  _get_simple_token_values(param_1,_process_challenge_token,param_2);
  return;
}

 (GhidraScript)  
===== login_vpn_server @ 00039f90 ===== (GhidraScript)  
int _login_vpn_server(long param_1,undefined8 param_2,int param_3)

{
  long lVar1;
  int iVar2;
  size_t sVar3;
  char *pcVar4;
  undefined *puVar5;
  undefined *puVar6;
  size_t sVar7;
  size_t sVar8;
  int iStack_207ac;
  int iStack_207a8;
  int iStack_207a4;
  int iStack_207a0;
  int iStack_2079c;
  int iStack_20798;
  int iStack_20794;
  FILE *pFStack_20790;
  uint auStack_20788 [2];
  int iStack_20780;
  int iStack_2077c;
  int iStack_20778;
  int iStack_20774;
  int iStack_20770;
  int iStack_2076c;
  undefined8 uStack_20768;
  long lStack_20760;
  int iStack_20754;
  char acStack_20750 [1024];
  int iStack_20350;
  undefined1 auStack_2034c [256];
  undefined1 auStack_2024c [256];
  undefined1 auStack_2014c [260];
  char acStack_20048 [48];
  undefined1 auStack_20018 [4096];
  char acStack_1f018 [520];
  undefined1 auStack_1ee10 [513];
  undefined1 auStack_1ec0f [257];
  undefined1 auStack_1eb0e [4097];
  undefined1 auStack_1db0d [4097];
  undefined1 auStack_1cb0c [4097];
  undefined1 auStack_1bb0b [1024];
  undefined1 auStack_1b70b [256];
  undefined1 auStack_1b60b [21003];
  int iStack_16400;
  char cStack_163fc;
  byte bStack_163fb;
  char cStack_163fa;
  undefined1 uStack_163f8;
  uint uStack_163f7;
  byte bStack_163f1;
  char acStack_163ec [513];
  char acStack_161eb [3880];
  char acStack_152c3 [67429];
  char local_4b5e;
  byte local_4b1e;
  undefined1 auStack_4b1d [2560];
  char acStack_411d [260];
  char local_4019;
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  iStack_20770 = 1;
  iStack_20774 = 0;
  iStack_20778 = 0;
  iStack_2077c = 0x8a0b;
  iStack_2076c = param_3;
  uStack_20768 = param_2;
  lStack_20760 = param_1;
  _memset(acStack_1f018,0,0x200);
  _memset(auStack_20018,0,0x1000);
  iStack_20780 = _array_vpn_is_zero_trust();
  if ((((iStack_20780 == 1) && (sVar3 = _strlen((char *)(lStack_20760 + 0x2a0)), sVar3 != 0)) &&
      (pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"ANsession"), pcVar4 != (char *)0x0)) &&
     ((pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"+"), pcVar4 != (char *)0x0 &&
      (pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"="), pcVar4 != (char *)0x0)))) {
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"common.c",&DAT_000022d0,"session cookie exist, don\'t need to login\n")
      ;
    }
    if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
      _array_vpn_logprint(1,"common.c",&DAT_000022d2,"session cookie=%s\n",lStack_20760 + 0x2a0);
    }
    iStack_20754 = 0;
  }
  else {
    _memset(&_auth_method,0,0xc12);
    ___memset_chk(uStack_20768,0,(long)iStack_2076c,0xffffffffffffffff);
    if (((*(uint *)(lStack_20760 + 0x5e58) & 0x100000) == 0) &&
       ((*(uint *)(lStack_20760 + 0x5e58) & 0x200000) == 0)) {
      iVar2 = _is_client_cert_auth_failed(iStack_20770);
      if (iVar2 == 0) {
        if (*(int *)(lStack_20760 + 0x50) == 0) {
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"common.c",&DAT_000022e5,
                                "begin to get virtual site\'s aaa method\n");
          }
          _memset(&iStack_16400,0,0x163ea);
          iStack_20770 = _get_aaa_method(lStack_20760,&iStack_16400);
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"common.c",&DAT_000022e9,
                                "login_vpn_server: get_aaa_method finished, client_update_oem_on: %d\n"
                                ,local_4b1e);
          }
          iVar2 = _is_client_cert_auth_failed(iStack_20770);
          if (iVar2 == 0) {
            ___memset_chk(lStack_20760 + 0xf9f8,0,0x104,0xffffffffffffffff);
            sVar3 = _strlen(acStack_411d);
            if ((sVar3 != 0) &&
               (___strncpy_chk(lStack_20760 + 0xf9f8,acStack_411d,0x103,0x104),
               _array_vpn_log_level_ < 2)) {
              _array_vpn_logprint(1,"common.c",&DAT_000022f3,
                                  "get server version finish, version(%s).\n",lStack_20760 + 0xf9f8)
              ;
            }
            *(undefined1 *)(lStack_20760 + 0xfafc) = 0;
            if (local_4019 == '\0') {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"common.c",&DAT_000022fd,
                                    "server disable sandbox, _AN_support_sandbox = 0,  update before login:%d\n"
                                    ,local_4b1e);
              }
            }
            else {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"common.c",&DAT_000022f8,
                                    "server enable sandbox flag(_AN_support_sandbox = %d), access token: %s, update before login:%d\n"
                                    ,local_4019,auStack_4b1d,local_4b1e);
              }
              *(char *)(lStack_20760 + 0xfafc) = local_4019;
            }
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"common.c",&DAT_00002300,
                                  "login_vpn_server: client_update_oem_on is %d\n",local_4b1e);
            }
            *(undefined4 *)(lStack_20760 + 0xfb00) = 0;
            if (local_4b1e != 0) {
              *(uint *)(lStack_20760 + 0xfb00) = (uint)local_4b1e;
            }
            if (*(int *)(lStack_20760 + 0xfb00) == 0x5f) {
              iStack_20770 = _do_client_update_check(lStack_20760);
            }
            else {
              iStack_20770 = _do_client_update_check(lStack_20760);
            }
            if (iStack_20770 == 0) {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"common.c",&DAT_00002315,
                                    "login_vpn_server: client don\'t need to update.\n");
              }
              iVar2 = _array_vpn_is_zero_trust();
              if ((((iVar2 == 0) &&
                   (pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"ANsession"),
                   pcVar4 != (char *)0x0)) &&
                  (pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"+"), pcVar4 != (char *)0x0)) &&
                 (pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"="), pcVar4 != (char *)0x0)) {
                if (_array_vpn_log_level_ < 2) {
                  _array_vpn_logprint(1,"common.c",&DAT_0000231e,
                                      "session cookie exist, don\'t need to login\n");
                }
                if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
                  _array_vpn_logprint(1,"common.c",&DAT_00002320,"session cookie=%s\n",
                                      lStack_20760 + 0x2a0);
                }
                _set_netauth_token(auStack_4b1d,uStack_20768,iStack_2076c);
                _save_netauth_token(auStack_4b1d);
                iStack_20754 = 0;
              }
              else {
                _memset(&_current_session,0,0x10b08);
                _current_session = 0xffffffff;
                if (local_4b5e != '\0') {
                  if (_array_vpn_log_level_ < 2) {
                    _array_vpn_logprint(1,"common.c",&DAT_0000232e,
                                        "aaa_info.server_cert_check_on is %d\n",local_4b5e);
                  }
                  lVar1 = lStack_20760;
                  sVar3 = _strlen(acStack_1f018);
                  iStack_20770 = _vpncallback(lVar1,0x2a,0,acStack_1f018,sVar3 & 0xffffffff,0,0);
                  if (iStack_20770 != 0) {
                    if (_array_vpn_log_level_ < 4) {
                      _array_vpn_logprint(3,"common.c",&DAT_00002337,"verify server cert failed.\n")
                      ;
                    }
                    iStack_20754 = iStack_20770;
                    goto LAB_0003c215;
                  }
                }
                if (*(int *)(lStack_20760 + 0x50) == 0) {
                  if ((iStack_20770 == 0) && (iStack_16400 != 0)) {
                    *(int *)(lStack_20760 + 0x98) = iStack_16400;
                    *(undefined1 *)(lStack_20760 + 0x84a0) = uStack_163f8;
                    *(uint *)(lStack_20760 + 0x84a4) = uStack_163f7;
                    if (_array_vpn_log_level_ < 2) {
                      _array_vpn_logprint(1,"common.c",&DAT_00002349,
                                          "get app client flag finished:mp_flag(%d).\n",uStack_163f7
                                         );
                    }
                    _gUnresolvedFlag = (uint)((uStack_163f7 & 4) != 0);
                    if (_array_vpn_log_level_ < 2) {
                      _array_vpn_logprint(1,"common.c",&DAT_00002352,
                                          "get app unresolved flag finished:%d.\n",_gUnresolvedFlag)
                      ;
                    }
                    if ((cStack_163fc != '\0') && (_array_vpn_log_level_ < 2)) {
                      _array_vpn_logprint(1,"common.c",&DAT_00002354,
                                          "hardware id is enabled, hardwareid type=%d.\n",
                                          bStack_163fb);
                    }
                    if ((cStack_163fc != '\0') &&
                       (sVar3 = _strlen((char *)(lStack_20760 + 0x5106)), sVar3 == 0)) {
                      iStack_2077c = 0x8a0b;
                      ___memset_chk(auStack_1ee10,0,0x8a0b,0x8a0b);
                      auStack_20788[0] = (uint)bStack_163fb;
                      if (_array_vpn_log_level_ < 2) {
                        _array_vpn_logprint(1,"common.c",&DAT_0000235b,"hardware id type=%d.\n",
                                            auStack_20788[0]);
                      }
                      iStack_20770 = _vpncallback(lStack_20760,0x1a,0,auStack_20788,4,auStack_1ee10,
                                                  &iStack_2077c);
                      if ((iStack_20770 != 0) || (iStack_2077c == 0)) {
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"common.c",&DAT_0000235e,
                                              "hardware id callback isn\'t processed by upper layer.\n"
                                             );
                        }
                        *(undefined4 *)(lStack_20760 + 0x54) = 0x3c;
                        iStack_20754 = 0x3c;
                        goto LAB_0003c215;
                      }
                      if (*(int *)(lStack_20760 + 0x50) != 0) {
                        *(undefined4 *)(lStack_20760 + 0x54) = 0x29;
                        iStack_20754 = 0x29;
                        goto LAB_0003c215;
                      }
                      ___strncpy_chk(lStack_20760 + 0x5106,auStack_1ee10,0xff,0x100);
                      if (_array_vpn_log_level_ < 2) {
                        _array_vpn_logprint(1,"common.c",&DAT_00002365,
                                            "hardware id callback processed successfully.\n");
                      }
                    }
                    if ((cStack_163fa == '\0') ||
                       (iStack_20770 = _do_client_security_check(lStack_20760,&iStack_16400),
                       iStack_20754 = iStack_20770, iStack_20770 == 0)) {
                      pFStack_20790 = _fopen("/var/log/iSecSP/csSessionFlag","r");
                      if (pFStack_20790 == (FILE *)0x0) {
                        if (_array_vpn_log_level_ < 3) {
                          _array_vpn_logprint(2,"common.c",&DAT_0000237d,
                                              "failed to open \'csSessionFlag\' from client temp path\n"
                                             );
                        }
                      }
                      else {
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"common.c",&DAT_00002381,
                                              "open CSsessionFlag file success\n");
                        }
                        _memset(acStack_20048,0,0x25);
                        _fgets(acStack_20048,0x25,pFStack_20790);
                        _fclose(pFStack_20790);
                        sVar3 = _strlen(acStack_20048);
                        if (sVar3 != 0) {
                          if (_array_vpn_log_level_ < 2) {
                            sVar3 = _strlen(acStack_20048);
                            _array_vpn_logprint(1,"common.c",&DAT_00002387,
                                                "get CSsessionFlag from local file success:%s. len:%d\n"
                                                ,acStack_20048,sVar3);
                          }
                          iVar2 = _strcmp(acStack_20048,"getCSSession=true");
                          if (iVar2 == 0) {
                            if (_array_vpn_log_level_ < 2) {
                              _array_vpn_logprint(1,"common.c",&DAT_0000238a,
                                                  "app client get clientsecurity session finish, go to cleanup!\n"
                                                 );
                            }
                            iStack_20754 = iStack_20770;
                            goto LAB_0003c215;
                          }
                        }
                      }
                      if (_array_vpn_log_level_ < 1) {
                        _array_vpn_logprint(0,"common.c",&DAT_00002391,
                                            "begin to login virtual site\n");
                      }
                      do {
                        if (((*(uint *)(lStack_20760 + 0x5e58) & 0x20) != 0) &&
                           (iVar2 = _app_login_use_devid(lStack_20760), iVar2 == 0)) {
                          iStack_20754 = 0;
                          break;
                        }
                        if (*(int *)(lStack_20760 + 0x50) != 0) {
                          *(undefined4 *)(lStack_20760 + 0x54) = 0x29;
                          iStack_20754 = 0x29;
                          break;
                        }
                        _g_new_sms_flag = 0;
                        iStack_20794 = 0;
                        if (_array_vpn_log_level_ < 2) {
                          puVar5 = &UNK_00001300 + lStack_20760;
                          puVar6 = &UNK_00001501 + lStack_20760;
                          sVar3 = _strlen(&DAT_00001602 + lStack_20760);
                          sVar7 = _strlen(&UNK_00002603 + lStack_20760);
                          sVar8 = _strlen(&UNK_00003604 + lStack_20760);
                          _array_vpn_logprint(1,"common.c",&DAT_0000239e,
                                              "Detect if user saved auth info: method:%s, uname:%s, mima_len:%d, mima1_len:%d, mima2_len:%d\n"
                                              ,puVar5,puVar6,sVar3,sVar7,sVar8);
                        }
                        sVar3 = _strlen(&UNK_00001300 + lStack_20760);
                        if ((((sVar3 != 0) &&
                             (sVar3 = _strlen(&UNK_00001501 + lStack_20760), sVar3 != 0)) &&
                            (sVar3 = _strlen(&DAT_00001602 + lStack_20760), sVar3 != 0)) &&
                           (sVar3 = _strlen(&UNK_00002603 + lStack_20760), sVar3 != 0)) {
                          for (iStack_20798 = 0; iStack_20798 < (int)(uint)bStack_163f1;
                              iStack_20798 = iStack_20798 + 1) {
                            if (_array_vpn_log_level_ < 2) {
                              _array_vpn_logprint(1,"common.c",&DAT_000023a3,
                                                  "Detect if new redius save mima behavior: method:%d, desc:%s, name:%s\n"
                                                  ,iStack_20798,
                                                  acStack_161eb + (long)iStack_20798 * 0x1b3b,
                                                  acStack_163ec + (long)iStack_20798 * 0x1b3b);
                            }
                            pcVar4 = _strstr(acStack_161eb + (long)iStack_20798 * 0x1b3b,
                                             "(radius_save_pwd)");
                            if ((pcVar4 != (char *)0x0) &&
                               (iVar2 = _strcmp(acStack_163ec + (long)iStack_20798 * 0x1b3b,
                                                &UNK_00001300 + lStack_20760), iVar2 == 0)) {
                              if (_array_vpn_log_level_ < 2) {
                                _array_vpn_logprint(1,"common.c",&DAT_000023a6,
                                                    "Detect it is new radius save mima behavior\n");
                              }
                              iStack_20794 = 1;
                              break;
                            }
                          }
                        }
                        if (iStack_20794 == 0) {
                          for (iStack_2079c = 0; iStack_2079c < (int)(uint)bStack_163f1;
                              iStack_2079c = iStack_2079c + 1) {
                            if (_array_vpn_log_level_ < 2) {
                              _array_vpn_logprint(1,"common.c",&DAT_000023b1,
                                                  "Detect if new redius save mima behavior: method:%d, desc:%s, name:%s. vcode_url:%s\n"
                                                  ,iStack_2079c,
                                                  acStack_161eb + (long)iStack_2079c * 0x1b3b,
                                                  acStack_163ec + (long)iStack_2079c * 0x1b3b,
                                                  acStack_152c3 + (long)iStack_2079c * 0x1b3b);
                            }
                            sVar3 = _strlen(acStack_152c3 + (long)iStack_2079c * 0x1b3b);
                            if ((sVar3 != 0) &&
                               (iVar2 = _strcmp(acStack_163ec + (long)iStack_2079c * 0x1b3b,
                                                &UNK_00001300 + lStack_20760), iVar2 == 0)) {
                              if (_array_vpn_log_level_ < 2) {
                                _array_vpn_logprint(1,"common.c",&DAT_000023b4,
                                                                                                        
                                                  "Detect it with vcode need input, set new_radis_flag to 1\n"
                                                  );
                              }
                              iStack_20794 = 1;
                              break;
                            }
                          }
                        }
                        if ((((*(uint *)(lStack_20760 + 0x5e58) & 0x400000) != 0) &&
                            (iStack_20794 != 0)) && (iStack_20794 = 0, _array_vpn_log_level_ < 2)) {
                          _array_vpn_logprint(1,"common.c",&DAT_000023c0,
                                              "This is linux cmdline, can not support new radius, set new_radis_flag to 0\n"
                                             );
                        }
                        iStack_207a0 = _vpn_need_auth_info(lStack_20760);
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"common.c",&DAT_000023c5,
                                              "do_login: new_radis_flag:%d, need_auth_info:%d\n",
                                              iStack_20794,iStack_207a0);
                        }
                        if ((iStack_20794 == 1) || (iStack_207a0 == 1)) {
                          iStack_2077c = 0x8a0b;
                          ___memset_chk(auStack_1ee10,0,0x8a0b,0x8a0b);
                          _memset(&_g_aaa_auth_input,0,0x8a0b);
                          if ((*(uint *)(lStack_20760 + 0x5e58) & 0x400000) == 0) {
                            for (iStack_207a4 = 0; iStack_207a4 < (int)(uint)bStack_163f1;
                                iStack_207a4 = iStack_207a4 + 1) {
                              pcVar4 = _strstr(acStack_161eb + (long)iStack_207a4 * 0x1b3b,
                                               "(sms_single_step)");
                              if (pcVar4 != (char *)0x0) {
                                _g_new_sms_flag = 1;
                                break;
                              }
                            }
                          }
                          else {
                            iStack_20794 = 0;
                            if (_array_vpn_log_level_ < 2) {
                              _array_vpn_logprint(1,"common.c",&DAT_000023ce,
                                                  "This is linux cmdline, can not support new sms, set g_new_sms_flag to 0\n"
                                                 );
                            }
                          }
                          ___sprintf_chk(auStack_1ee10,0,0x201,"%s",&UNK_00001300 + lStack_20760);
                          ___sprintf_chk(auStack_1ec0f,0,0x101,"%s",&UNK_00001501 + lStack_20760);
                          ___sprintf_chk(auStack_1eb0e,0,&DAT_00001001,"%s",
                                         &DAT_00001602 + lStack_20760);
                          ___sprintf_chk(auStack_1db0d,0,&DAT_00001001,"%s",
                                         &UNK_00002603 + lStack_20760);
                          ___sprintf_chk(auStack_1cb0c,0,&DAT_00001001,"%s",
                                         &UNK_00003604 + lStack_20760);
                          ___sprintf_chk(auStack_1bb0b,0,0x400,"%s",lStack_20760 + 0x4605);
                          ___sprintf_chk(auStack_1b70b,0,0x100,"%s",lStack_20760 + 0x4e05);
                          ___sprintf_chk(auStack_1b60b,0,0x201,"%s",&UNK_00004f05 + lStack_20760);
                          iStack_20770 = _vpncallback(lStack_20760,0xd,iStack_20774,&iStack_16400,
                                                      0x163ea,auStack_1ee10,&iStack_2077c);
                          if (_g_new_sms_flag == 1) {
                            if (_array_vpn_log_level_ < 2) {
                              _array_vpn_logprint(1,"common.c",&DAT_000023e8,
                                                  "waitting input data....\n");
                            }
                            for (iStack_207a8 = 0; iStack_207a8 < 0x708;
                                iStack_207a8 = iStack_207a8 + 1) {
                              sVar3 = _strlen(&_g_aaa_auth_input);
                              if (((sVar3 != 0) && (sVar3 = _strlen(&DAT_00358201), sVar3 == 0)) &&
                                 ((sVar3 = _strlen(&DAT_00358302), sVar3 == 0 &&
                                  (pcVar4 = _strstr(&_g_aaa_auth_input,"user_cancel_the_aaa"),
                                  pcVar4 != (char *)0x0)))) {
                                if (_array_vpn_log_level_ < 2) {
                                  _array_vpn_logprint(1,"common.c",&DAT_000023ee,
                                                      "do_sms: sdk received user cancel request\n");
                                }
                                _memset(&_g_aaa_auth_input,0,0x8a0b);
                                iStack_2077c = 0;
                                iStack_20770 = 0x3c;
                                break;
                              }
                              sVar3 = _strlen(&_g_aaa_auth_input);
                              if ((sVar3 != 0) || (sVar3 = _strlen(&DAT_00358201), sVar3 != 0)) {
                                _memcpy(auStack_1ee10,&_g_aaa_auth_input,0x8a0b);
                                iStack_20770 = 0;
                                break;
                              }
                              _usleep(100000);
                            }
                            if (_array_vpn_log_level_ < 2) {
                              _array_vpn_logprint(1,"common.c",&DAT_00002400,"received input data\n"
                                                 );
                            }
                          }
                          if ((iStack_20770 != 0) || (iStack_2077c == 0)) {
                            if (_array_vpn_log_level_ < 2) {
                              _array_vpn_logprint(1,"common.c",&DAT_00002404,
                                                  "login callback isn\'t prcessed by upper layer, ret:%d, input_len:%d\n"
                                                  ,iStack_20770,iStack_2077c);
                            }
                            *(undefined4 *)(lStack_20760 + 0x54) = 0x3c;
                            iStack_20754 = iStack_20770;
                            break;
                          }
                          _copy_auth_input(lStack_20760,auStack_1ee10);
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"common.c",&DAT_0000240a,
                                              "login with aaa method: %s, devName:%s, customer1:%s\n"
                                              ,&UNK_00001300 + lStack_20760,
                                              &UNK_00004f05 + lStack_20760,lStack_20760 + 0x4605);
                        }
                        iVar2 = _strcmp(&UNK_00001300 + lStack_20760,
                                        "oauth_get_session_callback_arraynetworks_flag");
                        if ((iVar2 == 0) ||
                           (iVar2 = _strcmp(&UNK_00001300 + lStack_20760,
                                            "oauth_get_session_for_web_app_flag"), iVar2 == 0)) {
                          if (_array_vpn_log_level_ < 2) {
                            _array_vpn_logprint(1,"common.c",&DAT_0000240d,
                                                "oauth_flag is true, start to callback VPN_OAUTH_SESSION\n"
                                               );
                          }
                          iVar2 = _strcmp(&UNK_00001300 + lStack_20760,
                                          "oauth_get_session_for_web_app_flag");
                          if (iVar2 == 0) {
                            iStack_20350 = 1;
                          }
                          else {
                            iStack_20350 = _atoi(&UNK_00004f05 + lStack_20760);
                          }
                          ___sprintf_chk(auStack_2034c,0,0x100,"%s",&DAT_00001602 + lStack_20760);
                          ___sprintf_chk(auStack_2024c,0,0x100,"%s",&UNK_00002603 + lStack_20760);
                          ___sprintf_chk(auStack_2014c,0,0x100,"%s",&UNK_00003604 + lStack_20760);
                          iStack_20770 = _vpncallback(lStack_20760,0xcd,0,&iStack_20350,0x304,
                                                      acStack_20750,0x400);
                          if ((iStack_20770 != 0) || (sVar3 = _strlen(acStack_20750), sVar3 == 0)) {
                            if (_array_vpn_log_level_ < 2) {
                              _array_vpn_logprint(1,"common.c",&DAT_0000241e,
                                                  "login callback failed due to get oauth session failed.\n"
                                                 );
                            }
                            *(undefined4 *)(lStack_20760 + 0x54) = 0x85;
                            iStack_20754 = 0x85;
                            break;
                          }
                          ___sprintf_chk(lStack_20760 + 0x2a0,0,&DAT_00001020,"%s",acStack_20750);
                        }
                        iVar2 = _array_vpn_is_zero_trust();
                        if ((((iVar2 == 0) &&
                             (pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"ANsession"),
                             pcVar4 != (char *)0x0)) &&
                            (pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"+"),
                            pcVar4 != (char *)0x0)) &&
                           (pcVar4 = _strstr((char *)(lStack_20760 + 0x2a0),"="),
                           pcVar4 != (char *)0x0)) {
                          if (_array_vpn_log_level_ < 2) {
                            _array_vpn_logprint(1,"common.c",&DAT_00002426,
                                                "session cookie received, return success\n");
                          }
                          if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
                            _array_vpn_logprint(1,"common.c",&DAT_00002428,"session cookie=%s\n",
                                                lStack_20760 + 0x2a0);
                          }
                          iStack_20754 = 0;
                          break;
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"common.c",&DAT_0000242d,"start to login_ag...\n");
                        }
                        iStack_207ac = 1;
                        iStack_20770 = _login_ag(lStack_20760,&iStack_16400,1,&iStack_207ac);
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"common.c",&DAT_00002430,
                                              "login_ag finished, ret:%d\n",iStack_20770);
                        }
                        if (*(int *)(lStack_20760 + 0x50) != 0) {
                          if (_array_vpn_log_level_ < 2) {
                            _array_vpn_logprint(1,"common.c",&DAT_00002433,
                                                "login finished, however received manually_stop, then exit sdk thread\n"
                                               );
                          }
                          *(undefined4 *)(lStack_20760 + 0x54) = 0x29;
                          iStack_20754 = 0x29;
                          break;
                        }
                        if (iStack_20770 == 0x352) {
                          iStack_20754 = iStack_20770;
                          break;
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"common.c",&DAT_0000244c,
                                              "login_ag finished, ret:%d, count:%d, aaa_new_method_num:%d\n"
                                              ,iStack_20770,iStack_20778,iStack_207ac);
                        }
                        if (iStack_207ac < 1) {
                          iStack_20778 = 0xb;
                        }
                        if (((((iStack_20770 != 0x25) && (iStack_20770 != 0x70)) &&
                             ((iStack_20770 != 0x34 &&
                              ((iStack_20770 != 0x85 && (iStack_20770 != 0x8b)))))) ||
                            (iStack_20778 = iStack_20778 + 1, 9 < iStack_20778)) ||
                           (iVar2 = _vpn_has_callback(lStack_20760), iVar2 == 0)) goto LAB_0003c106;
                        if (iStack_20770 == 0x25) {
                          if (_array_vpn_log_level_ < 2) {
                            _array_vpn_logprint(1,"common.c",&DAT_00002458,
                                                "failed to login, wrong user or mima, try again\n");
                          }
                        }
                        else if (iStack_20770 == 0x70) {
                          if (_array_vpn_log_level_ < 2) {
                            _array_vpn_logprint(1,"common.c",&DAT_0000245c,
                                                "failed to login, locked, try again\n");
                          }
                        }
                        else if (iStack_20770 == 0x85) {
                          if (_array_vpn_log_level_ < 2) {
                            _array_vpn_logprint(1,"common.c",&DAT_00002460,
                                                "user cancel qrcode login, try again\n");
                          }
                        }
                        else if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"common.c",&DAT_00002464,
                                              "ERR_CHOOSE_METHOD, try again\n");
                        }
                        iVar2 = _strcmp(&UNK_00001300 + lStack_20760,
                                        "oauth_get_session_callback_arraynetworks_flag");
                        if (iVar2 == 0) {
                          ___memset_chk(&UNK_00001300 + lStack_20760,0,0x201,0xffffffffffffffff);
                          ___memset_chk(&DAT_00001602 + lStack_20760,0,&DAT_00001001,
                                        0xffffffffffffffff);
                          ___memset_chk(&UNK_00002603 + lStack_20760,0,&DAT_00001001,
                                        0xffffffffffffffff);
                          ___memset_chk(&UNK_00003604 + lStack_20760,0,&DAT_00001001,
                                        0xffffffffffffffff);
                          ___memset_chk(&UNK_00001501 + lStack_20760,0,0x101,0xffffffffffffffff);
                          ___memset_chk(lStack_20760 + 0x4e05,0,0x100,0xffffffffffffffff);
                          ___memset_chk(&UNK_00004f05 + lStack_20760,0,0x201,0xffffffffffffffff);
                        }
                        else {
                          ___memset_chk(&DAT_00001602 + lStack_20760,0,&DAT_00001001,
                                        0xffffffffffffffff);
                          ___memset_chk(&UNK_00002603 + lStack_20760,0,&DAT_00001001,
                                        0xffffffffffffffff);
                          ___memset_chk(&UNK_00003604 + lStack_20760,0,&DAT_00001001,
                                        0xffffffffffffffff);
                          ___memset_chk(lStack_20760 + 0x4e05,0,0x100,0xffffffffffffffff);
                          ___memset_chk(&UNK_00004f05 + lStack_20760,0,0x201,0xffffffffffffffff);
                        }
                        iStack_20774 = iStack_20770;
                      } while( true );
                    }
                  }
                  else {
                    if (_array_vpn_log_level_ < 4) {
                      _array_vpn_logprint(3,"common.c",&DAT_0000233f,"failed to get aaa method.\n");
                    }
                    *(undefined4 *)(lStack_20760 + 0x54) = 0x26;
                    iStack_20754 = 0x26;
                  }
                }
                else {
                  *(undefined4 *)(lStack_20760 + 0x54) = 0x29;
                  iStack_20754 = 0x29;
                }
              }
            }
            else {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"common.c",&DAT_00002319,
                                    "login_vpn_server: client need to update\n");
              }
              *(int *)(lStack_20760 + 0x54) = iStack_20770;
              iStack_20754 = iStack_20770;
            }
          }
          else {
            if (_array_vpn_log_level_ < 4) {
              _array_vpn_logprint(3,"common.c",&DAT_000022eb,"client cert auth failed.\n");
            }
            *(int *)(lStack_20760 + 0x54) = iStack_20770;
            iStack_20754 = iStack_20770;
          }
        }
        else {
          *(undefined4 *)(lStack_20760 + 0x54) = 0x29;
          iStack_20754 = 0x29;
        }
      }
      else {
        if (_array_vpn_log_level_ < 4) {
          _array_vpn_logprint(3,"common.c",&DAT_000022e0,"client cert auth failed.\n");
        }
        *(int *)(lStack_20760 + 0x54) = iStack_20770;
        iStack_20754 = iStack_20770;
      }
    }
    else {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"common.c",&DAT_000022dc,
                            "This is vpnd or DesktopDirect, no need login_vpn_server, break\n");
      }
      iStack_20754 = 0;
    }
  }
  goto LAB_0003c215;
LAB_0003c106:
  if (iStack_20770 == 0) {
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"common.c",&DAT_00002477,"login successfully, method name: %s\n",
                          &UNK_00001300 + lStack_20760);
    }
    _set_auth_info(lStack_20760,&iStack_16400);
    _set_netauth_token(auStack_4b1d,uStack_20768,iStack_2076c);
  }
  else if (_array_vpn_log_level_ < 4) {
    _array_vpn_logprint(3,"common.c",&DAT_00002475,"failed to login, error %d\n",iStack_20770);
  }
  if ((iStack_20770 != 0) && (_array_vpn_log_level_ < 4)) {
    _array_vpn_logprint(3,"common.c",&DAT_0000247c,"failed to login, error %d\n",iStack_20770);
  }
  iStack_20754 = iStack_20770;
LAB_0003c215:
  if (*(long *)PTR____stack_chk_guard_002e4060 == local_10) {
    return iStack_20754;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

 (GhidraScript)  
===== array_vpn_tcs_connect @ 0003db20 ===== (GhidraScript)  
int _array_vpn_tcs_connect(undefined8 *param_1)

{
  __uint16_t _Var1;
  int iVar2;
  undefined4 *puVar3;
  size_t sVar4;
  size_t sVar5;
  char acStack_12c58 [18];
  __uint16_t _Stack_12c46;
  uint uStack_12c44;
  undefined4 uStack_12c40;
  int iStack_12c3c;
  undefined8 *puStack_12c38;
  int iStack_12c2c;
  char acStack_12c28 [264];
  undefined4 uStack_12b20;
  __uint16_t _Stack_12b1a;
  undefined8 uStack_12af0;
  undefined8 uStack_12ae8;
  undefined8 uStack_12ae0;
  undefined8 uStack_12ad8;
  int iStack_12acc;
  undefined1 auStack_12a84 [256];
  char acStack_12984 [260];
  char acStack_12880 [23440];
  undefined1 auStack_ccf0 [40];
  uint local_ccc8;
  char local_2018 [8192];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_002e4060;
  iStack_12c3c = 1;
  puStack_12c38 = param_1;
  _memset(local_2018,0,0x2000);
  if (puStack_12c38 == (undefined8 *)0x0) {
    iStack_12c2c = 0x2a;
  }
  else {
    local_ccc8 = local_ccc8 | 0x80000;
    iStack_12c3c = _copy_session_data(&uStack_12b20);
    iStack_12c2c = iStack_12c3c;
    if (iStack_12c3c == 0) {
      iStack_12c3c = _ssl_connect_try_all_methods(&uStack_12b20);
      if (iStack_12c3c == 0) {
        puVar3 = _malloc(0x30);
        if (puVar3 == (undefined4 *)0x0) {
          iStack_12c3c = 8;
        }
        else {
          *(undefined8 *)(puVar3 + 2) = uStack_12af0;
          *(undefined8 *)(puVar3 + 8) = uStack_12ad8;
          *puVar3 = uStack_12b20;
          *(undefined8 *)(puVar3 + 4) = uStack_12ae8;
          *(undefined8 *)(puVar3 + 6) = uStack_12ae0;
          _Stack_12c46 = __OSSwapInt16(_Stack_12b1a);
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"common.c",&DAT_0000271d,"array_vpn_tcs_connect: start...\n");
          }
          _memset(acStack_12c28,0,0x100);
          _array_get_spa_sess(acStack_12c28,0x100);
          sVar4 = _strlen(acStack_12984);
          if (sVar4 == 0) {
            if (_Stack_12c46 == 0x1bb) {
              uStack_12c40 = ___sprintf_chk(local_2018,0,0x2000,
                                            "GET %s/vpntunnel HTTP/1.1\r\nHost: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: SSPVPN\r\nclientid: %s\r\nAppid:DesktopDirect\r\n\r\n"
                                            ,"/prx/000/http/localhost",auStack_12a84,acStack_12880,
                                            acStack_12c28,auStack_ccf0);
            }
            else {
              uStack_12c40 = ___sprintf_chk(local_2018,0,0x2000,
                                            "GET %s/vpntunnel HTTP/1.1\r\nHost: %s:%u\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: SSPVPN\r\nclientid: %s\r\nAppid:DesktopDirect\r\n\r\n"
                                            ,"/prx/000/http/localhost",auStack_12a84,_Stack_12c46,
                                            acStack_12880,acStack_12c28,auStack_ccf0);
            }
          }
          else if (_Stack_12c46 == 0x1bb) {
            uStack_12c40 = ___sprintf_chk(local_2018,0,0x2000,
                                          "GET %s/vpntunnel HTTP/1.1\r\nHost: %s\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: SSPVPN\r\nclientid: %s\r\nAppid:DesktopDirect\r\n\r\n"
                                          ,"/prx/000/http/localhost",acStack_12984,acStack_12880,
                                          acStack_12c28,auStack_ccf0);
          }
          else {
            uStack_12c40 = ___sprintf_chk(local_2018,0,0x2000,
                                          "GET %s/vpntunnel HTTP/1.1\r\nHost: %s:%u\r\nCookie: %s;ANStandalone=true;SPA-Session=%s\r\nappid: SSPVPN\r\nclientid: %s\r\nAppid:DesktopDirect\r\n\r\n"
                                          ,"/prx/000/http/localhost",acStack_12984,_Stack_12c46,
                                          acStack_12880,acStack_12c28,auStack_ccf0);
          }
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"common.c",&DAT_00002739,"array_vpn_tcs_connect: start22...\n");
          }
          if (_g_printlogtraffic == 0) {
            sVar4 = _strlen(acStack_12984);
            _Var1 = _Stack_12c46;
            if (sVar4 == 0) {
              if (_array_vpn_log_level_ < 2) {
                sVar4 = _strlen(acStack_12880);
                sVar5 = _strlen(acStack_12c28);
                _array_vpn_logprint(1,"common.c",&DAT_00002745,
                                    "array_vpn_tcs_connect: open tunnel req: GET %s/vpntunnel HTTP/1.1\r\nHost: %s:%u\r\nCookie len: %d, spa len: %d\r\nappid: SSPVPN\r\nclientid: %s\r\nAppid:DesktopDirect\n"
                                    ,"/prx/000/http/localhost",auStack_12a84,_Var1,sVar4,sVar5,
                                    auStack_ccf0);
              }
            }
            else if (_array_vpn_log_level_ < 2) {
              sVar4 = _strlen(acStack_12880);
              sVar5 = _strlen(acStack_12c28);
              _array_vpn_logprint(1,"common.c",&DAT_00002741,
                                  "array_vpn_tcs_connect: open tunnel req: GET %s/vpntunnel HTTP/1.1\r\nHost: %s:%u\r\nCookie len: %d, spa len:%d\r\nappid: SSPVPN\r\nclientid: %s\r\nAppid:DesktopDirect\n"
                                  ,"/prx/000/http/localhost",acStack_12984,_Var1,sVar4,sVar5,
                                  auStack_ccf0);
            }
          }
          else if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"common.c",&DAT_0000273b,
                                "array_vpn_tcs_connect: open tunnel req: [%s]\n",local_2018);
          }
          iStack_12c3c = _SSL_write(uStack_12ae8,local_2018,uStack_12c40);
          if (iStack_12c3c < 1) {
            if (_array_vpn_log_level_ < 4) {
              _array_vpn_logprint(3,"common.c",&DAT_0000274b,
                                  "array_vpn_tcs_connect: failed to write to ssl tunnel to open tunnel\n"
                                 );
            }
            iStack_12c3c = 3;
          }
          else {
            _stat_send_add((long)iStack_12c3c);
            _memset(local_2018,0,0x2000);
            iStack_12c3c = _ssl_get_page(&uStack_12b20,0,local_2018,0x1fff,&uStack_12c44);
            if (iStack_12c3c == 0) {
              local_2018[uStack_12c44] = '\0';
              iVar2 = _strncasecmp(local_2018,"HTTP/1.1 302 Redirect",0x15);
              if (iVar2 == 0) {
                if (_array_vpn_log_level_ < 4) {
                  _array_vpn_logprint(3,"common.c",&DAT_0000275b,
                                      "array_vpn_tcs_connect: invalid response [%s]\n",local_2018);
                }
                iStack_12c3c = 6;
              }
              else {
                iVar2 = _strncasecmp(local_2018,"HTTP/1.1 200 OK",0xf);
                if (iVar2 == 0) {
                  _memset(acStack_12c58,0,0x10);
                  acStack_12c58[0] = '\x0f';
                  iStack_12c3c = _SSL_write(uStack_12ae8,acStack_12c58,0x10);
                  if (iStack_12c3c < 1) {
                    if (_array_vpn_log_level_ < 4) {
                      _array_vpn_logprint(3,"common.c",&DAT_0000276b,
                                          "array_vpn_tcs_connect: send request to start tcs failed\n"
                                         );
                    }
                    iStack_12c3c = 3;
                  }
                  else {
                    _stat_send_add((long)iStack_12c3c);
                    _memset(acStack_12c58,0,0x10);
                    iStack_12c3c = _SSL_read(uStack_12ae8,acStack_12c58,0x10);
                    if ((iStack_12c3c == 0x10) && (acStack_12c58[0] == '\x0f')) {
                      *puStack_12c38 = puVar3;
                      iStack_12c3c = 0;
                    }
                    else {
                      if (_array_vpn_log_level_ < 4) {
                        _array_vpn_logprint(3,"common.c",&DAT_00002775,
                                            "array_vpn_tcs_connect: failed to get response of start tcs\n"
                                           );
                      }
                      iStack_12c3c = 2;
                    }
                  }
                }
                else {
                  if (_array_vpn_log_level_ < 4) {
                    _array_vpn_logprint(3,"common.c",&DAT_00002761,
                                        "array_vpn_tcs_connect: response is invalid:\n[%s]\n",
                                        local_2018);
                  }
                  iStack_12c3c = 0x28;
                }
              }
            }
            else if (_array_vpn_log_level_ < 4) {
              _array_vpn_logprint(3,"common.c",&DAT_00002755,
                                  "array_vpn_tcs_connect: failed to recv response from server\n");
            }
          }
        }
      }
      else {
        if (_array_vpn_log_level_ < 3) {
          _array_vpn_logprint(2,"common.c",&DAT_00002709,
                              "array_vpn_tcs_connect: connect to VPN server failed, error: %d",
                              iStack_12c3c);
        }
        iStack_12c3c = iStack_12acc;
      }
      if (iStack_12c3c != 0) {
        _free_sessoin_data(&uStack_12b20);
      }
      iStack_12c2c = iStack_12c3c;
    }
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_18) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return iStack_12c2c;
}

 (GhidraScript)  
===== get_ag_l3vpn_config @ 00056570 ===== (GhidraScript)  
int _get_ag_l3vpn_config(undefined4 *param_1)

{
  long lVar1;
  uint uVar2;
  __uint16_t _Var3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  __uint32_t _Var8;
  in_addr_t iVar9;
  size_t sVar10;
  undefined4 *puVar11;
  char *pcVar12;
  undefined8 uVar13;
  long lVar14;
  char *pcVar15;
  undefined4 *puVar16;
  undefined8 in_stack_fffffffffffefa50;
  undefined8 in_stack_fffffffffffefa60;
  undefined4 *puVar17;
  undefined4 uVar18;
  undefined8 in_stack_fffffffffffefa68;
  int iStack_1054c;
  int iStack_10534;
  int iStack_1051c;
  uint uStack_10444;
  uint uStack_10440;
  uint uStack_1043c;
  char *pcStack_10438;
  uint uStack_10430;
  int iStack_1042c;
  int iStack_10424;
  undefined4 *puStack_10420;
  uint uStack_10414;
  long lStack_10408;
  undefined1 auStack_10400 [12];
  undefined4 uStack_103f4;
  undefined4 uStack_103f0;
  undefined4 uStack_103ec;
  undefined4 uStack_103e8;
  undefined1 uStack_103d8;
  undefined1 uStack_103d7;
  byte bStack_103d6;
  byte bStack_103d5;
  byte bStack_103d4;
  byte bStack_103d3;
  uint uStack_103d0;
  undefined4 uStack_103cc;
  undefined4 uStack_103c8;
  undefined4 uStack_103c4;
  undefined4 uStack_103c0;
  uint uStack_103bc;
  undefined4 uStack_103b8;
  undefined4 uStack_103b4;
  undefined4 uStack_103b0;
  undefined1 auStack_103a8 [4];
  uint uStack_103a4;
  undefined4 uStack_103a0;
  undefined4 uStack_10380;
  undefined4 uStack_1037c;
  undefined4 uStack_10378;
  undefined1 uStack_10374;
  undefined1 uStack_10373;
  char acStack_10370 [12];
  uint uStack_10364;
  undefined1 auStack_10360 [16];
  undefined1 auStack_10350 [6];
  __uint16_t _Stack_1034a;
  int iStack_10348;
  int iStack_10344;
  undefined4 *puStack_10340;
  undefined1 auStack_10338 [256];
  char acStack_10238 [256];
  undefined1 auStack_10138 [256];
  char acStack_10038 [65544];
  
  uVar7 = (undefined4)((ulong)in_stack_fffffffffffefa68 >> 0x20);
  uVar5 = (undefined4)((ulong)in_stack_fffffffffffefa50 >> 0x20);
  uVar6 = (undefined4)((ulong)in_stack_fffffffffffefa60 >> 0x20);
  lVar1 = *(long *)PTR____stack_chk_guard_002e4060;
  puStack_10340 = param_1;
  _memset(acStack_10038,0,0xffff);
  lStack_10408 = 0;
  uStack_10414 = 0;
  puStack_10420 = (undefined4 *)0x0;
  _memset(auStack_10138,0,0x100);
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"get_config.c",0x618,"get_ag_l3vpn_config start...\n");
  }
  _memset(acStack_10038,0,0xffff);
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"get_config.c",0x621,
                        "get_ag_l3vpn_config start open tunnel, ipsec_enable=%d\n",
                        puStack_10340[0x4c45]);
  }
  _memset(acStack_10238,0,0x100);
  _array_get_spa_sess(acStack_10238,0x100);
  puVar16 = puStack_10340 + 0x178c;
  sVar10 = _strlen((char *)(puStack_10340 + 0x178c));
  ___strncpy_chk(auStack_10138,puVar16,sVar10,0x100);
  _Stack_1034a = __OSSwapInt16(*(__uint16_t *)((long)puStack_10340 + 6));
  if (_Stack_1034a == 0) {
    _Stack_1034a = __OSSwapInt16(*(__uint16_t *)((long)puStack_10340 + 0x16));
  }
  if ((_Stack_1034a == 0) && (_array_vpn_log_level_ < 4)) {
    _array_vpn_logprint(3,"get_config.c",0x63e,"get_ag_l3vpn_config: invalid port number %u\n",0);
  }
  _memset(auStack_10338,0,0x100);
  if (puStack_10340[0x4c45] == 1) {
    ___snprintf_chk(auStack_10338,0x100,0,0x100,"%s","IPSec");
  }
  else {
    ___snprintf_chk(auStack_10338,0x100,0,0x100,"%s","SSPVPN");
  }
  sVar10 = _strlen((char *)(puStack_10340 + 0x67));
  if (sVar10 == 0) {
    iVar4 = _is_ipv6_host(puStack_10340 + 0x27);
    _Var3 = _Stack_1034a;
    if (iVar4 == 0) {
      if (_Stack_1034a == 0x1bb) {
        puVar16 = puStack_10340 + 0x27;
        pcVar15 = acStack_10238;
        pcVar12 = (char *)(puStack_10340 + 0xa8);
        uVar5 = _get_current_dev_type();
        puVar17 = (undefined4 *)CONCAT44(uVar6,uVar5);
        iStack_10344 = ___snprintf_chk(acStack_10038,0xffff,0,0xffff,
                                       "GET %s/vpntunnel HTTP/1.1\r\nHost: %s\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n"
                                       ,"/prx/000/http/localhost",puVar16,pcVar15,pcVar12,puVar17,
                                       auStack_10338,puStack_10340 + 0x178c,auStack_10138,
                                       &UNK_00004f05 + (long)puStack_10340);
      }
      else {
        puVar16 = puStack_10340 + 0x27;
        pcVar12 = acStack_10238;
        puVar17 = puStack_10340 + 0xa8;
        uVar6 = _get_current_dev_type();
        pcVar15 = (char *)CONCAT44(uVar5,(uint)_Var3);
        iStack_10344 = ___snprintf_chk(acStack_10038,0xffff,0,0xffff,
                                       "GET %s/vpntunnel HTTP/1.1\r\nHost: %s:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n"
                                       ,"/prx/000/http/localhost",puVar16,pcVar15,pcVar12,puVar17,
                                       CONCAT44(uVar7,uVar6),auStack_10338,puStack_10340 + 0x178c,
                                       auStack_10138,&UNK_00004f05 + (long)puStack_10340);
      }
    }
    else if (_Stack_1034a == 0x1bb) {
      puVar16 = puStack_10340 + 0x27;
      pcVar15 = acStack_10238;
      pcVar12 = (char *)(puStack_10340 + 0xa8);
      uVar5 = _get_current_dev_type();
      puVar17 = (undefined4 *)CONCAT44(uVar6,uVar5);
      iStack_10344 = ___snprintf_chk(acStack_10038,0xffff,0,0xffff,
                                     "GET %s/vpntunnel HTTP/1.1\r\nHost: [%s]\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n"
                                     ,"/prx/000/http/localhost",puVar16,pcVar15,pcVar12,puVar17,
                                     auStack_10338,puStack_10340 + 0x178c,auStack_10138,
                                     &UNK_00004f05 + (long)puStack_10340);
    }
    else {
      puVar16 = puStack_10340 + 0x27;
      pcVar12 = acStack_10238;
      puVar17 = puStack_10340 + 0xa8;
      uVar6 = _get_current_dev_type();
      pcVar15 = (char *)CONCAT44(uVar5,(uint)_Var3);
      iStack_10344 = ___snprintf_chk(acStack_10038,0xffff,0,0xffff,
                                     "GET %s/vpntunnel HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n"
                                     ,"/prx/000/http/localhost",puVar16,pcVar15,pcVar12,puVar17,
                                     CONCAT44(uVar7,uVar6),auStack_10338,puStack_10340 + 0x178c,
                                     auStack_10138,&UNK_00004f05 + (long)puStack_10340);
    }
  }
  else {
    iVar4 = _is_ipv6_host(puStack_10340 + 0x67);
    _Var3 = _Stack_1034a;
    if (iVar4 == 0) {
      if (_Stack_1034a == 0x1bb) {
        puVar16 = puStack_10340 + 0x67;
        pcVar15 = acStack_10238;
        pcVar12 = (char *)(puStack_10340 + 0xa8);
        uVar5 = _get_current_dev_type();
        puVar17 = (undefined4 *)CONCAT44(uVar6,uVar5);
        iStack_10344 = ___snprintf_chk(acStack_10038,0xffff,0,0xffff,
                                       "GET %s/vpntunnel HTTP/1.1\r\nHost: %s\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n"
                                       ,"/prx/000/http/localhost",puVar16,pcVar15,pcVar12,puVar17,
                                       auStack_10338,puStack_10340 + 0x178c,auStack_10138,
                                       &UNK_00004f05 + (long)puStack_10340);
      }
      else {
        puVar16 = puStack_10340 + 0x67;
        pcVar12 = acStack_10238;
        puVar17 = puStack_10340 + 0xa8;
        uVar6 = _get_current_dev_type();
        pcVar15 = (char *)CONCAT44(uVar5,(uint)_Var3);
        iStack_10344 = ___snprintf_chk(acStack_10038,0xffff,0,0xffff,
                                       "GET %s/vpntunnel HTTP/1.1\r\nHost: %s:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n"
                                       ,"/prx/000/http/localhost",puVar16,pcVar15,pcVar12,puVar17,
                                       CONCAT44(uVar7,uVar6),auStack_10338,puStack_10340 + 0x178c,
                                       auStack_10138,&UNK_00004f05 + (long)puStack_10340);
      }
    }
    else if (_Stack_1034a == 0x1bb) {
      puVar16 = puStack_10340 + 0x67;
      pcVar15 = acStack_10238;
      pcVar12 = (char *)(puStack_10340 + 0xa8);
      uVar5 = _get_current_dev_type();
      puVar17 = (undefined4 *)CONCAT44(uVar6,uVar5);
      iStack_10344 = ___snprintf_chk(acStack_10038,0xffff,0,0xffff,
                                     "GET %s/vpntunnel HTTP/1.1\r\nHost: [%s]\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n"
                                     ,"/prx/000/http/localhost",puVar16,pcVar15,pcVar12,puVar17,
                                     auStack_10338,puStack_10340 + 0x178c,auStack_10138,
                                     &UNK_00004f05 + (long)puStack_10340);
    }
    else {
      puVar16 = puStack_10340 + 0x67;
      pcVar12 = acStack_10238;
      puVar17 = puStack_10340 + 0xa8;
      uVar6 = _get_current_dev_type();
      pcVar15 = (char *)CONCAT44(uVar5,(uint)_Var3);
      iStack_10344 = ___snprintf_chk(acStack_10038,0xffff,0,0xffff,
                                     "GET %s/vpntunnel HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\r\n\r\n"
                                     ,"/prx/000/http/localhost",puVar16,pcVar15,pcVar12,puVar17,
                                     CONCAT44(uVar7,uVar6),auStack_10338,puStack_10340 + 0x178c,
                                     auStack_10138,&UNK_00004f05 + (long)puStack_10340);
    }
  }
  if (_g_printlogtraffic == 0) {
    sVar10 = _strlen((char *)(puStack_10340 + 0x67));
    if (sVar10 == 0) {
      iVar4 = _is_ipv6_host(puStack_10340 + 0x27);
      _Var3 = _Stack_1034a;
      uVar6 = (undefined4)((ulong)puVar17 >> 0x20);
      uVar5 = (undefined4)((ulong)puVar16 >> 0x20);
      if (iVar4 == 0) {
        if (_array_vpn_log_level_ < 2) {
          puVar11 = puStack_10340 + 0x27;
          pcVar15 = (char *)_strlen((char *)(puStack_10340 + 0xa8));
          pcVar12 = (char *)_strlen(acStack_10238);
          uVar7 = _get_current_dev_type();
          puVar16 = (undefined4 *)CONCAT44(uVar5,(uint)_Var3);
          puVar17 = (undefined4 *)CONCAT44(uVar6,uVar7);
          _array_vpn_logprint(1,"get_config.c",0x692,
                              "open tunnel req: GET %s/vpntunnel HTTP/1.1\r\nHost: %s:%u\r\nCookie len: %d, SPA-Session len:%d\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\n"
                              ,"/prx/000/http/localhost",puVar11,puVar16,pcVar15,pcVar12,puVar17,
                              auStack_10338,puStack_10340 + 0x178c,auStack_10138,
                              &UNK_00004f05 + (long)puStack_10340);
        }
      }
      else if (_array_vpn_log_level_ < 2) {
        puVar11 = puStack_10340 + 0x27;
        pcVar15 = (char *)_strlen((char *)(puStack_10340 + 0xa8));
        pcVar12 = (char *)_strlen(acStack_10238);
        uVar7 = _get_current_dev_type();
        puVar16 = (undefined4 *)CONCAT44(uVar5,(uint)_Var3);
        puVar17 = (undefined4 *)CONCAT44(uVar6,uVar7);
        _array_vpn_logprint(1,"get_config.c",0x68e,
                            "open tunnel req: GET %s/vpntunnel HTTP/1.1\r\nHost: [%s]:%u\r\nCookie len: %d, SPA-Session len:%d\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\n"
                            ,"/prx/000/http/localhost",puVar11,puVar16,pcVar15,pcVar12,puVar17,
                            auStack_10338,puStack_10340 + 0x178c,auStack_10138,
                            &UNK_00004f05 + (long)puStack_10340);
      }
    }
    else {
      iVar4 = _is_ipv6_host(puStack_10340 + 0x67);
      _Var3 = _Stack_1034a;
      uVar6 = (undefined4)((ulong)puVar17 >> 0x20);
      uVar5 = (undefined4)((ulong)puVar16 >> 0x20);
      if (iVar4 == 0) {
        if (_array_vpn_log_level_ < 2) {
          puVar11 = puStack_10340 + 0x67;
          pcVar15 = (char *)_strlen((char *)(puStack_10340 + 0xa8));
          pcVar12 = (char *)_strlen(acStack_10238);
          uVar7 = _get_current_dev_type();
          puVar16 = (undefined4 *)CONCAT44(uVar5,(uint)_Var3);
          puVar17 = (undefined4 *)CONCAT44(uVar6,uVar7);
          _array_vpn_logprint(1,"get_config.c",0x687,
                              "open tunnel req: GET %s/vpntunnel HTTP/1.1\r\nHost: %s:%u\r\nCookie len: %d, SPA-Session len:%d\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\n"
                              ,"/prx/000/http/localhost",puVar11,puVar16,pcVar15,pcVar12,puVar17,
                              auStack_10338,puStack_10340 + 0x178c,auStack_10138,
                              &UNK_00004f05 + (long)puStack_10340);
        }
      }
      else if (_array_vpn_log_level_ < 2) {
        puVar11 = puStack_10340 + 0x67;
        pcVar15 = (char *)_strlen((char *)(puStack_10340 + 0xa8));
        pcVar12 = (char *)_strlen(acStack_10238);
        uVar7 = _get_current_dev_type();
        puVar16 = (undefined4 *)CONCAT44(uVar5,(uint)_Var3);
        puVar17 = (undefined4 *)CONCAT44(uVar6,uVar7);
        _array_vpn_logprint(1,"get_config.c",0x683,
                            "open tunnel req: GET %s/vpntunnel HTTP/1.1\r\nHost: [%s]:%u\r\nCookie len: %d, SPA-Session len:%d\r\nx-devtype: %d\r\nappid: %s\r\nclientid: %s\r\ncpuid: %s\r\nhostname: %s\r\nPAYLOAD-IP-VERSION: 6\n"
                            ,"/prx/000/http/localhost",puVar11,puVar16,pcVar15,pcVar12,puVar17,
                            auStack_10338,puStack_10340 + 0x178c,auStack_10138,
                            &UNK_00004f05 + (long)puStack_10340);
      }
    }
  }
  else if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"get_config.c",0x67b,"open tunnel req: [%s]\n",acStack_10038);
  }
  iStack_10348 = _SSL_write(*(undefined8 *)(puStack_10340 + 0xe),acStack_10038,iStack_10344);
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"get_config.c",0x698,"SSL_write finished: ret:%d\n",iStack_10348);
  }
  if (puStack_10340[0x14] == 0) {
    if (iStack_10348 < 1) {
      if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"get_config.c",0x69b,
                            "get_ag_config: failed to write to ssl tunnel to open tunnel\n");
      }
      iStack_10348 = 3;
    }
    else {
      _stat_send_add((long)iStack_10348);
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"get_config.c",0x6a1,"write open tunnel request to ssl tunnel\n");
      }
      _memset(acStack_10038,0,0xffff);
      iStack_10348 = _ssl_get_page(puStack_10340,0,acStack_10038,0xfffe,auStack_10350);
      if (iStack_10348 == 0) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"get_config.c",0x6aa,"open tunnel response: [%s]\n",acStack_10038);
        }
        iVar4 = _strncasecmp(acStack_10038,"HTTP/1.1 302 Redirect",0x15);
        if (iVar4 == 0) {
          if (_array_vpn_log_level_ < 4) {
            _array_vpn_logprint(3,"get_config.c",0x6ad,"get_ag_config: invalid response [%s]\n",
                                acStack_10038);
          }
          iStack_10348 = 6;
        }
        else {
          iVar4 = _strncasecmp(acStack_10038,"HTTP/1.1 200 OK",0xf);
          if (iVar4 != 0) {
            iVar4 = _strncasecmp(acStack_10038,"HTTP/1.1 201 OK",0xf);
            if (iVar4 != 0) {
              if (_array_vpn_log_level_ < 4) {
                _array_vpn_logprint(3,"get_config.c",0x6b9,
                                    "get_ag_config: response is invalid:\n[%s]\n",acStack_10038);
              }
              iStack_10348 = 0x28;
              goto LAB_00059ba5;
            }
            puStack_10340[0x2125] = 1;
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"get_config.c",0x6b6,
                                  "get_ag_config: response is json protocol\n");
            }
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"get_config.c",0x6b7,"get_ag_config: buf: %s.\n",acStack_10038);
            }
          }
          _memset(auStack_10360,0,0x10);
          auStack_10360[0] = 0x50;
          iStack_10348 = _SSL_write(*(undefined8 *)(puStack_10340 + 0xe),auStack_10360,0x10);
          if (puStack_10340[0x14] == 0) {
            if (iStack_10348 < 1) {
              if (_array_vpn_log_level_ < 4) {
                _array_vpn_logprint(3,"get_config.c",0x6c5,
                                    "get_ag_config: failed to send common config request\n");
              }
              iStack_10348 = 3;
            }
            else {
              _stat_send_add((long)iStack_10348);
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"get_config.c",0x6cb,
                                    "write common config request to ssl tunnel\n");
              }
              iStack_10348 = _ssl_readn(puStack_10340,acStack_10370,0x10);
              if (puStack_10340[0x14] == 0) {
                if (iStack_10348 < 1) {
                  if (_array_vpn_log_level_ < 4) {
                    _array_vpn_logprint(3,"get_config.c",0x6d0,
                                        "get_ag_config: failed to get common config head\n");
                  }
                  iStack_10348 = 2;
                }
                else {
                  _stat_recv_add((long)iStack_10348);
                  if (acStack_10370[0] == 'Q') {
                    puStack_10420 = _malloc((ulong)uStack_10364);
                    if (puStack_10420 == (undefined4 *)0x0) {
                      if (_array_vpn_log_level_ < 4) {
                        _array_vpn_logprint(3,"get_config.c",0x6df,"failed to allocate memory\n");
                      }
                      iStack_10348 = 8;
                    }
                    else {
                      if (puStack_10340[0x2125] == 1) {
                        ___memset_chk(puStack_10420,0,uStack_10364,0xffffffffffffffff);
                        for (; uStack_10414 < uStack_10364;
                            uStack_10414 = iStack_10348 + uStack_10414) {
                          iStack_10348 = _SSL_read(*(undefined8 *)(puStack_10340 + 0xe),
                                                   (long)puStack_10420 + (ulong)uStack_10414,
                                                   uStack_10364 - uStack_10414);
                          if (puStack_10340[0x14] != 0) {
                            puStack_10340[0x15] = 0x29;
                            iStack_10348 = 0x29;
                            goto LAB_00059ba5;
                          }
                          if (iStack_10348 < 1) {
                            if (_array_vpn_log_level_ < 4) {
                              _array_vpn_logprint(3,"get_config.c",0x6ea,
                                                  "get_ag_config: failed to get common config data\n"
                                                 );
                            }
                            iStack_10348 = 2;
                            goto LAB_00059ba5;
                          }
                          _stat_recv_add((long)iStack_10348);
                        }
                        if (_array_vpn_log_level_ < 2) {
                          puVar16 = puStack_10420;
                          _array_vpn_logprint(1,"get_config.c",0x6f2,
                                              "datalen %d, offset is %d, common cfg is:\n%s\n",
                                              uStack_10364,uStack_10414,puStack_10420);
                        }
                        lStack_10408 = _cJSON_Parse(puStack_10420);
                        if (lStack_10408 == 0) {
                          if (_array_vpn_log_level_ < 4) {
                            uVar13 = _cJSON_GetErrorPtr();
                            _array_vpn_logprint(3,"get_config.c",0x6f7,
                                                "get_ag_config: failed to parse common config, error: %s\n"
                                                ,uVar13);
                          }
                          iStack_10348 = 0x28;
                          goto LAB_00059ba5;
                        }
                        lVar14 = _cJSON_GetObjectItem(lStack_10408,"netpool_flag");
                        if (lVar14 != 0) {
                          uStack_103a4 = *(uint *)(lVar14 + 0x28);
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"get_config.c",0x701,
                                              "get_ag_config: netpool flags: [0x%x]\n",uStack_103a4)
                          ;
                        }
                        uVar2 = uStack_103a4;
                        if ((uStack_103a4 & 0x100) == 0) {
                          if (_array_vpn_log_level_ < 4) {
                            _Var8 = __OSSwapInt32(uStack_103a4);
                            _array_vpn_logprint(3,"get_config.c",0x704,
                                                "get_ag_config: l3vpn is not enabled, flags: [%x], %x\n"
                                                ,uVar2,_Var8);
                          }
                          iStack_10348 = 0x28;
                          goto LAB_00059ba5;
                        }
                        puStack_10340[0x46d8] = uStack_103a4;
                        lVar14 = _cJSON_GetObjectItem(lStack_10408,"keepalive_interval");
                        if (lVar14 != 0) {
                          uStack_103a0 = *(undefined4 *)(lVar14 + 0x28);
                          puStack_10340[0x4455] = uStack_103a0;
                          if (_array_vpn_log_level_ < 2) {
                            _array_vpn_logprint(1,"get_config.c",0x70f,"keep alive interval: [%d]\n"
                                                ,puStack_10340[0x4455]);
                          }
                        }
                        lVar14 = _cJSON_GetObjectItem(lStack_10408,"allow_speed_tunnel");
                        if (lVar14 != 0) {
                          uStack_10374 = (undefined1)*(undefined4 *)(lVar14 + 0x28);
                        }
                        lVar14 = _cJSON_GetObjectItem(lStack_10408,"speed_tunnel_encryption");
                        if (lVar14 != 0) {
                          uStack_10373 = (undefined1)*(undefined4 *)(lVar14 + 0x28);
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"get_config.c",0x71d,
                                              "speed tunnel: [%d], encrypt: [%d]\n",uStack_10374,
                                              uStack_10373);
                        }
                        *(undefined1 *)((long)puStack_10340 + 0x112f2) = uStack_10374;
                        *(undefined1 *)((long)puStack_10340 + 0x112f3) = uStack_10373;
                        ___memset_chk((long)puStack_10340 + 0x121a1,0,0x104,0xffffffffffffffff);
                        lVar14 = _cJSON_GetObjectItem(lStack_10408,"cur_acsmode");
                        if (lVar14 != 0) {
                          sVar10 = _strlen(*(char **)(lVar14 + 0x20));
                          iStack_10344 = (int)sVar10;
                          if (iStack_10344 + 1 < 0x105) {
                            iStack_1051c = iStack_10344 + 1;
                          }
                          else {
                            iStack_1051c = 0x104;
                          }
                          ___memcpy_chk((long)puStack_10340 + 0x121a1,*(undefined8 *)(lVar14 + 0x20)
                                        ,(long)iStack_1051c,0xffffffffffffffff);
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"get_config.c",0x727,
                                              "get_ag_config: get current access mode:%s.\n",
                                              (long)puStack_10340 + 0x121a1);
                        }
                        ___memset_chk((long)puStack_10340 + 0x123a9,0,0x400,0xffffffffffffffff);
                        ___memset_chk((long)puStack_10340 + 0x122a5,0,0x104,0xffffffffffffffff);
                        lVar14 = _cJSON_GetObjectItem(lStack_10408,"redirect_url");
                        if (lVar14 != 0) {
                          sVar10 = _strlen(*(char **)(lVar14 + 0x20));
                          iStack_10344 = (int)sVar10;
                          if (iStack_10344 + 1 < 0x401) {
                            iStack_10534 = iStack_10344 + 1;
                          }
                          else {
                            iStack_10534 = 0x400;
                          }
                          ___memcpy_chk((long)puStack_10340 + 0x123a9,*(undefined8 *)(lVar14 + 0x20)
                                        ,(long)iStack_10534,0xffffffffffffffff);
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"get_config.c",0x731,
                                              "get_ag_config: get current redirect_url:%s.\n",
                                              (long)puStack_10340 + 0x123a9);
                        }
                        lVar14 = _cJSON_GetObjectItem(lStack_10408,"redirect_browser");
                        if (lVar14 != 0) {
                          sVar10 = _strlen(*(char **)(lVar14 + 0x20));
                          iStack_10344 = (int)sVar10;
                          if (iStack_10344 + 1 < 0x105) {
                            iStack_1054c = iStack_10344 + 1;
                          }
                          else {
                            iStack_1054c = 0x104;
                          }
                          ___memcpy_chk((long)puStack_10340 + 0x122a5,*(undefined8 *)(lVar14 + 0x20)
                                        ,(long)iStack_1054c,0xffffffffffffffff);
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"get_config.c",0x738,
                                              "get_ag_config: get current redirect_browser:%s.\n",
                                              (long)puStack_10340 + 0x122a5);
                        }
                        _parse_ag_hostmap(puStack_10340,lStack_10408);
                        _parse_ag_launch_command(puStack_10340,lStack_10408,1);
                        _parse_ag_launch_command(puStack_10340,lStack_10408,0);
                      }
                      else {
                        iStack_10348 = _ssl_readn(puStack_10340,auStack_103a8,0x38);
                        if (puStack_10340[0x14] != 0) {
                          puStack_10340[0x15] = 0x29;
                          iStack_10348 = 0x29;
                          goto LAB_00059ba5;
                        }
                        if (iStack_10348 < 1) {
                          if (_array_vpn_log_level_ < 4) {
                            _array_vpn_logprint(3,"get_config.c",0x768,
                                                "get_ag_config: failed to get common config data\n")
                            ;
                          }
                          iStack_10348 = 2;
                          goto LAB_00059ba5;
                        }
                        _stat_recv_add((long)iStack_10348);
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"get_config.c",0x76f,
                                              "get_ag_config: netpool flags: [0x%x]\n",uStack_103a4)
                          ;
                        }
                        uVar2 = uStack_103a4;
                        if ((uStack_103a4 & 0x100) == 0) {
                          if (_array_vpn_log_level_ < 4) {
                            _Var8 = __OSSwapInt32(uStack_103a4);
                            _array_vpn_logprint(3,"get_config.c",0x772,
                                                "get_ag_config: l3vpn is not enabled, flags: [%x], %x\n"
                                                ,uVar2,_Var8);
                          }
                          iStack_10348 = 0x28;
                          goto LAB_00059ba5;
                        }
                        puStack_10340[0x46d8] = uStack_103a4;
                        puStack_10340[0x4455] = uStack_103a0;
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"get_config.c",0x77a,"keep alive interval: [%d]\n",
                                              puStack_10340[0x4455]);
                        }
                        if (_array_vpn_log_level_ < 2) {
                          _array_vpn_logprint(1,"get_config.c",0x77d,
                                              "speed tunnel: [%d], encrypt: [%d]\n",uStack_10374,
                                              uStack_10373);
                        }
                        *(undefined1 *)((long)puStack_10340 + 0x112f2) = uStack_10374;
                        *(undefined1 *)((long)puStack_10340 + 0x112f3) = uStack_10373;
                        _get_ag_hostmap(puStack_10340,uStack_10380);
                        _get_ag_launch_command(puStack_10340,uStack_1037c,1);
                        _get_ag_launch_command(puStack_10340,uStack_10378,0);
                      }
                      _memset(auStack_10400,0,0x30);
                      if (puStack_10340[0x4c45] == 1) {
                        auStack_10400[0] = 0x5d;
                      }
                      else {
                        auStack_10400[0] = 0x54;
                      }
                      uStack_103f4 = 0x20;
                      if (puStack_10340[0x4452] != 0) {
                        if (_array_vpn_log_level_ < 2) {
                          puVar16 = (undefined4 *)
                                    CONCAT44((int)((ulong)puVar16 >> 0x20),
                                             (uint)*(byte *)((long)puStack_10340 + 0x1114a));
                          pcVar15 = (char *)CONCAT44((int)((ulong)pcVar15 >> 0x20),
                                                     (uint)*(byte *)((long)puStack_10340 + 0x1114b))
                          ;
                          _array_vpn_logprint(1,"get_config.c",0x797,
                                              "get_ag_config: current virtual ip is %d.%d.%d.%d, must ignore it.\n"
                                              ,*(undefined1 *)(puStack_10340 + 0x4452),
                                              *(undefined1 *)((long)puStack_10340 + 0x11149),puVar16
                                              ,pcVar15);
                        }
                        uStack_103ec = puStack_10340[0x4452];
                        puStack_10340[0x4452] = 0;
                        if ((_g_wg_running == 1) || (_g_wg_running == 2)) {
                          _g_wg_running = 1;
                          uStack_103e8 = 1;
                        }
                      }
                      uStack_103f0 = _get_local_address(&uStack_103ec,5);
                      iStack_10424 = 0;
                      while( true ) {
                        uVar7 = (undefined4)((ulong)pcVar12 >> 0x20);
                        uVar18 = (undefined4)((ulong)puVar17 >> 0x20);
                        uVar6 = (undefined4)((ulong)pcVar15 >> 0x20);
                        uVar5 = (undefined4)((ulong)puVar16 >> 0x20);
                        if (4 < iStack_10424) break;
                        if (((&uStack_103ec)[iStack_10424] != 0) && (_array_vpn_log_level_ < 2)) {
                          puVar16 = (undefined4 *)
                                    CONCAT44(uVar5,(uint)*(byte *)((long)&uStack_103ec +
                                                                  (long)iStack_10424 * 4 + 2));
                          pcVar15 = (char *)CONCAT44(uVar6,(uint)*(byte *)((long)&uStack_103ec +
                                                                          (long)iStack_10424 * 4 + 3
                                                                          ));
                          _array_vpn_logprint(1,"get_config.c",0x7a7,
                                              "get_ag_config: get local adapter ip: %d.%d.%d.%d\n",
                                              *(undefined1 *)(&uStack_103ec + iStack_10424),
                                              *(undefined1 *)
                                               ((long)&uStack_103ec + (long)iStack_10424 * 4 + 1),
                                              puVar16,pcVar15);
                        }
                        iStack_10424 = iStack_10424 + 1;
                      }
                      iVar4 = _get_local_mac_address(&uStack_103d8,*puStack_10340);
                      if (iVar4 == 0) {
                        if (_array_vpn_log_level_ < 2) {
                          uVar13 = CONCAT44(uVar7,(uint)bStack_103d4);
                          _array_vpn_logprint(1,"get_config.c",0x7c2,
                                              "Found ether card for MAC: %02X:%02X:%02X:%02X:%02X:%02X\n"
                                              ,uStack_103d8,uStack_103d7,
                                              CONCAT44(uVar5,(uint)bStack_103d6),
                                              CONCAT44(uVar6,(uint)bStack_103d5),uVar13,
                                              CONCAT44(uVar18,(uint)bStack_103d3));
                          uVar7 = (undefined4)((ulong)uVar13 >> 0x20);
                        }
                      }
                      else if (_array_vpn_log_level_ < 4) {
                        _array_vpn_logprint(3,"get_config.c",0x7bd,
                                            "get_ag_config: failed to get local mac address\n");
                      }
                      iStack_10348 = _SSL_write(*(undefined8 *)(puStack_10340 + 0xe),auStack_10400,
                                                0x30);
                      if (puStack_10340[0x14] == 0) {
                        if (iStack_10348 < 1) {
                          if (_array_vpn_log_level_ < 4) {
                            _array_vpn_logprint(3,"get_config.c",0x7c9,
                                                "get_ag_config: failed to send netwrok config request\n"
                                               );
                          }
                          iStack_10348 = 3;
                        }
                        else {
                          _stat_send_add((long)iStack_10348);
                          if (_array_vpn_log_level_ < 2) {
                            _array_vpn_logprint(1,"get_config.c",1999,
                                                "write net config request to ssl tunnel\n");
                          }
                          iStack_10348 = _ssl_readn(puStack_10340,acStack_10370,0x10);
                          if (puStack_10340[0x14] == 0) {
                            if (iStack_10348 < 1) {
                              if (_array_vpn_log_level_ < 4) {
                                _array_vpn_logprint(3,"get_config.c",0x7d4,
                                                                                                        
                                                  "get_ag_config: failed to get network config response head: %d\n"
                                                  ,iStack_10348);
                              }
                              iStack_10348 = 2;
                            }
                            else {
                              _stat_recv_add((long)iStack_10348);
                              if ((acStack_10370[0] == 'U') || (acStack_10370[0] == '^')) {
                                if (puStack_10420 != (undefined4 *)0x0) {
                                  _free(puStack_10420);
                                }
                                puStack_10420 = _malloc((ulong)uStack_10364);
                                if (puStack_10420 == (undefined4 *)0x0) {
                                  if (_array_vpn_log_level_ < 4) {
                                    _array_vpn_logprint(3,"get_config.c",0x7e8,
                                                        "failed to allocate memory");
                                  }
                                  iStack_10348 = 8;
                                }
                                else {
                                  if (puStack_10340[0x2125] == 1) {
                                    ___memset_chk(puStack_10420,0,uStack_10364,0xffffffffffffffff);
                                    for (uStack_10414 = 0; uStack_10414 < uStack_10364;
                                        uStack_10414 = iStack_10348 + uStack_10414) {
                                      iStack_10348 = _SSL_read(*(undefined8 *)(puStack_10340 + 0xe),
                                                               (long)puStack_10420 +
                                                               (ulong)uStack_10414,
                                                               uStack_10364 - uStack_10414);
                                      if (puStack_10340[0x14] != 0) {
                                        puStack_10340[0x15] = 0x29;
                                        iStack_10348 = 0x29;
                                        goto LAB_00059ba5;
                                      }
                                      if (iStack_10348 < 1) {
                                        if (_array_vpn_log_level_ < 4) {
                                          _array_vpn_logprint(3,"get_config.c",0x7f4,
                                                                                                                            
                                                  "get_ag_config: failed to get common config data\n"
                                                  );
                                        }
                                        iStack_10348 = 2;
                                        goto LAB_00059ba5;
                                      }
                                      _stat_recv_add((long)iStack_10348);
                                    }
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x7fd,
                                                                                                                    
                                                  "datalen %d, offset %d, netconfig is:\n%s\n",
                                                  uStack_10364,uStack_10414,puStack_10420);
                                    }
                                    lStack_10408 = _cJSON_Parse(puStack_10420);
                                    if (lStack_10408 == 0) {
                                      if (_array_vpn_log_level_ < 4) {
                                        uVar13 = _cJSON_GetErrorPtr();
                                        _array_vpn_logprint(3,"get_config.c",0x802,
                                                                                                                        
                                                  "get_ag_config: failed to parse l3vpn config, error: %s\n"
                                                  ,uVar13);
                                      }
                                      iStack_10348 = 0x28;
                                      goto LAB_00059ba5;
                                    }
                                    lVar14 = _cJSON_GetObjectItem
                                                       (lStack_10408,"resource_group_flag");
                                    if (lVar14 != 0) {
                                      puStack_10340[0x46d9] = *(undefined4 *)(lVar14 + 0x28);
                                    }
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x80c,
                                                          "l3vpn resource flags: %d\n",
                                                          puStack_10340[0x46d9]);
                                    }
                                    if ((puStack_10340[0x46d9] & 1) != 0) {
                                      if (_array_vpn_log_level_ < 2) {
                                        _array_vpn_logprint(1,"get_config.c",0x80f,
                                                            "tunnel mode: full tunnel\n");
                                      }
                                      *(undefined1 *)(puStack_10340 + 0x44bc) = 1;
                                    }
                                    if (((puStack_10340[0x46d9] & 2) != 0) &&
                                       (_array_vpn_log_level_ < 2)) {
                                      _array_vpn_logprint(1,"get_config.c",0x814,
                                                          "client subnet: enable\n");
                                    }
                                    lVar14 = _cJSON_GetObjectItem(lStack_10408,"client_ipv4");
                                    if (lVar14 != 0) {
                                      puStack_10340[0x4452] = *(undefined4 *)(lVar14 + 0x28);
                                    }
                                    lVar14 = _cJSON_GetObjectItem(lStack_10408,"client_ipv4_mask");
                                    if (lVar14 != 0) {
                                      if (*(int *)(lVar14 + 0x28) == 0) {
                                        puStack_10340[0x4453] = 0xffffffff;
                                      }
                                      else {
                                        puStack_10340[0x4453] = *(undefined4 *)(lVar14 + 0x28);
                                      }
                                    }
                                    lVar14 = _cJSON_GetObjectItem(lStack_10408,"client_ipv6");
                                    if (lVar14 != 0) {
                                      sVar10 = _strlen(*(char **)(lVar14 + 0x20));
                                      iStack_10344 = (int)sVar10;
                                      ___memcpy_chk(puStack_10340 + 0x4456,
                                                    *(undefined8 *)(lVar14 + 0x20),
                                                    (long)(iStack_10344 + 1),0xffffffffffffffff);
                                    }
                                    lVar14 = _cJSON_GetObjectItem(lStack_10408,"client_ipv6_mask");
                                    if (lVar14 != 0) {
                                      sVar10 = _strlen(*(char **)(lVar14 + 0x20));
                                      iStack_10344 = (int)sVar10;
                                      ___memcpy_chk(puStack_10340 + 0x4478,
                                                    *(undefined8 *)(lVar14 + 0x20),
                                                    (long)(iStack_10344 + 1),0xffffffffffffffff);
                                    }
                                    if (puStack_10340[0x4452] != 0) {
                                      _Var8 = __OSSwapInt32(puStack_10340[0x4452] &
                                                            puStack_10340[0x4453]);
                                      _Var8 = __OSSwapInt32(_Var8 + 1);
                                      puStack_10340[0x4454] = _Var8;
                                      if (_array_vpn_log_level_ < 2) {
                                        _array_vpn_logprint(1,"get_config.c",0x834,
                                                            "IPv4:%d.%d.%d.%d, mask: %d.%d.%d.%d\n",
                                                            *(undefined1 *)(puStack_10340 + 0x4452),
                                                            *(undefined1 *)
                                                             ((long)puStack_10340 + 0x11149),
                                                            *(undefined1 *)
                                                             ((long)puStack_10340 + 0x1114a),
                                                            *(undefined1 *)
                                                             ((long)puStack_10340 + 0x1114b),
                                                            *(undefined1 *)(puStack_10340 + 0x4453),
                                                            *(undefined1 *)
                                                             ((long)puStack_10340 + 0x1114d),
                                                            *(undefined1 *)
                                                             ((long)puStack_10340 + 0x1114e),
                                                            *(undefined1 *)
                                                             ((long)puStack_10340 + 0x1114f));
                                      }
                                    }
                                    sVar10 = _strlen((char *)(puStack_10340 + 0x4456));
                                    if ((sVar10 != 0) &&
                                       (_array_vpn_get_ipv6_net
                                                  (puStack_10340 + 0x4456,puStack_10340 + 0x4478,0,
                                                   puStack_10340 + 0x449a),
                                       _array_vpn_log_level_ < 2)) {
                                      puVar16 = puStack_10340 + 0x4456;
                                      uVar5 = _array_vpn_get_ipv6_prefix(puStack_10340 + 0x4478);
                                      _array_vpn_logprint(1,"get_config.c",0x839,"IPv6:%s/%d\n",
                                                          puVar16,uVar5);
                                    }
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x83c,
                                                          "Include network list:\n");
                                    }
                                    _parse_ag_network(puStack_10340,lStack_10408,1);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x83e,
                                                          "Exclude network list:\n");
                                    }
                                    _parse_ag_network(puStack_10340,lStack_10408,0);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x840,
                                                          "parse_ag_network finished\n");
                                    }
                                    _parse_ag_inside_proxy(puStack_10340,lStack_10408);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x842,
                                                          "parse_ag_inside_proxy finished\n");
                                    }
                                    _parse_ag_dns(puStack_10340,lStack_10408);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x844,
                                                          "parse_ag_dns finished\n");
                                    }
                                    _parse_ag_search_domain(puStack_10340,lStack_10408);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x846,
                                                          "parse_ag_search_domain finished\n");
                                    }
                                    _parse_ag_network_detect(puStack_10340,lStack_10408);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x848,
                                                          "parse_ag_network_detect finished\n");
                                    }
                                    if ((puStack_10340[0x4c45] == 1) &&
                                       (_parse_ag_ipsec(puStack_10340,lStack_10408),
                                       _array_vpn_log_level_ < 2)) {
                                      _array_vpn_logprint(1,"get_config.c",0x84d,
                                                          "parse_ag_ipsec finished\n");
                                    }
                                  }
                                  else {
                                    _memset(&uStack_103d0,0,0x24);
                                    iStack_10348 = _ssl_readn(puStack_10340,&uStack_103d0,0x24);
                                    if (puStack_10340[0x14] != 0) {
                                      puStack_10340[0x15] = 0x29;
                                      iStack_10348 = 0x29;
                                      goto LAB_00059ba5;
                                    }
                                    if (iStack_10348 < 1) {
                                      if (_array_vpn_log_level_ < 4) {
                                        _array_vpn_logprint(3,"get_config.c",0x855,
                                                                                                                        
                                                  "get_ag_config: failed to get network config data\n"
                                                  );
                                      }
                                      iStack_10348 = 2;
                                      goto LAB_00059ba5;
                                    }
                                    _stat_recv_add((long)iStack_10348);
                                    puStack_10340[0x46d9] = uStack_103d0;
                                    if ((uStack_103d0 & 1) != 0) {
                                      if (_array_vpn_log_level_ < 2) {
                                        _array_vpn_logprint(1,"get_config.c",0x85f,
                                                            "tunnel mode: full tunnel\n");
                                      }
                                      *(undefined1 *)(puStack_10340 + 0x44bc) = 1;
                                    }
                                    if (((uStack_103d0 & 2) != 0) && (_array_vpn_log_level_ < 2)) {
                                      _array_vpn_logprint(1,"get_config.c",0x863,
                                                          "client subnet: enable\n");
                                    }
                                    puStack_10340[0x4452] = uStack_103c0;
                                    puStack_10340[0x4453] = uStack_103bc;
                                    _Var8 = __OSSwapInt32(puStack_10340[0x4452] &
                                                          puStack_10340[0x4453]);
                                    _Var8 = __OSSwapInt32(_Var8 + 1);
                                    puStack_10340[0x4454] = _Var8;
                                    *(undefined1 *)((long)puStack_10340 + 0x112f1) = 0;
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x86c,
                                                          "IP:%d.%d.%d.%d, mask: %d.%d.%d.%d\n",
                                                          (undefined1)uStack_103c0,
                                                          uStack_103c0._1_1_,
                                                          uStack_103c0 >> 0x10 & 0xff,
                                                          uStack_103c0 >> 0x18,
                                                          CONCAT44(uVar7,uStack_103bc) &
                                                          0xffffffff000000ff,
                                                          uStack_103bc >> 8 & 0xff,
                                                          uStack_103bc >> 0x10 & 0xff,
                                                          uStack_103bc >> 0x18);
                                    }
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x86e,
                                                          "Include network list:\n");
                                    }
                                    _get_ag_network(puStack_10340,uStack_103cc,1);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x870,
                                                          "Exclude network list:\n");
                                    }
                                    _get_ag_network(puStack_10340,uStack_103c8,0);
                                    _get_ag_inside_proxy(puStack_10340,uStack_103c4);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x874,
                                                          "get_ag_inside_proxy finished\n");
                                    }
                                    _get_ag_dns(puStack_10340,uStack_103b8);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x876,
                                                          "get_ag_dns finished\n");
                                    }
                                    _get_ag_wins(puStack_10340,uStack_103b4);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x878,
                                                          "get_ag_wins finished\n");
                                    }
                                    _get_ag_search_domain(puStack_10340,uStack_103b0);
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x87a,
                                                          "get_ag_search_domain finished\n");
                                    }
                                  }
                                  iStack_1042c = 0;
                                  sVar10 = _strlen((char *)(puStack_10340 + 0x2eef));
                                  if (sVar10 == 0) {
                                    if (*(long *)(puStack_10340 + 0x46d2) != 0) {
                                      for (uStack_1043c = 0;
                                          uStack_1043c < (uint)puStack_10340[0x46d0];
                                          uStack_1043c = uStack_1043c + 1) {
                                        if (_array_vpn_log_level_ < 2) {
                                          _array_vpn_logprint(1,"get_config.c",0x898,
                                                                                                                            
                                                  "hostmap config: index[%d], %s, %d.%d.%d.%d.\n",
                                                  uStack_1043c,
                                                  *(long *)(*(long *)(puStack_10340 + 0x46d2) +
                                                           (long)(int)uStack_1043c * 8) + 4,
                                                  **(undefined1 **)
                                                    (*(long *)(puStack_10340 + 0x46d2) +
                                                    (long)(int)uStack_1043c * 8),
                                                  *(undefined1 *)
                                                   (*(long *)(*(long *)(puStack_10340 + 0x46d2) +
                                                             (long)(int)uStack_1043c * 8) + 1),
                                                  *(undefined1 *)
                                                   (*(long *)(*(long *)(puStack_10340 + 0x46d2) +
                                                             (long)(int)uStack_1043c * 8) + 2),
                                                  *(undefined1 *)
                                                   (*(long *)(*(long *)(puStack_10340 + 0x46d2) +
                                                             (long)(int)uStack_1043c * 8) + 3));
                                        }
                                        _Var8 = __OSSwapInt32(**(__uint32_t **)
                                                                (*(long *)(puStack_10340 + 0x46d2) +
                                                                (long)(int)uStack_1043c * 8));
                                        if (((_Var8 == 7) &&
                                            (pcVar15 = _strstr((char *)(*(long *)(*(long *)(
                                                  puStack_10340 + 0x46d2) +
                                                  (long)(int)uStack_1043c * 8) + 4),"*."),
                                            pcVar15 == (char *)0x0)) &&
                                           (pcVar15 = _strstr((char *)(*(long *)(*(long *)(
                                                  puStack_10340 + 0x46d2) +
                                                  (long)(int)uStack_1043c * 8) + 4),".*"),
                                           pcVar15 == (char *)0x0)) {
                                          iVar4 = iStack_1042c + 1;
                                          if (0x10 < iVar4) {
                                            iStack_1042c = 0x10;
                                            break;
                                          }
                                          if (iVar4 == 1) {
                                            if (_array_vpn_log_level_ < 2) {
                                              _array_vpn_logprint(1,"get_config.c",0x8a5,
                                                                                                                                    
                                                  "hostmap config: netpool dns, need clear old dns first.\n"
                                                  );
                                            }
                                            for (uStack_10440 = 0;
                                                uStack_10440 < (uint)puStack_10340[0x46ca];
                                                uStack_10440 = uStack_10440 + 1) {
                                              *(undefined4 *)
                                               (*(long *)(puStack_10340 + 0x46cc) +
                                               (long)(int)uStack_10440 * 4) = 0;
                                            }
                                          }
                                          if (_array_vpn_log_level_ < 2) {
                                            _array_vpn_logprint(1,"get_config.c",0x8ac,
                                                                                                                                
                                                  "hostmap config: netpool dns add to dns config, index=%d, dns server=%s.\n"
                                                  ,iVar4,*(long *)(*(long *)(puStack_10340 + 0x46d2)
                                                                  + (long)(int)uStack_1043c * 8) + 4
                                                  );
                                          }
                                          iVar9 = _inet_addr((char *)(*(long *)(*(long *)(
                                                  puStack_10340 + 0x46d2) +
                                                  (long)(int)uStack_1043c * 8) + 4));
                                          *(in_addr_t *)
                                           (*(long *)(puStack_10340 + 0x46cc) +
                                           (long)iStack_1042c * 4) = iVar9;
                                          iStack_1042c = iVar4;
                                        }
                                      }
                                    }
                                  }
                                  else {
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x880,
                                                                                                                    
                                                  "custom dns config: netpool dns, need clear old dns first.\n"
                                                  );
                                    }
                                    for (uStack_10430 = 0;
                                        uStack_10430 < (uint)puStack_10340[0x46ca];
                                        uStack_10430 = uStack_10430 + 1) {
                                      *(undefined4 *)
                                       (*(long *)(puStack_10340 + 0x46cc) +
                                       (long)(int)uStack_10430 * 4) = 0;
                                    }
                                    pcStack_10438 = _strtok((char *)(puStack_10340 + 0x2eef),";");
                                    do {
                                      if (pcStack_10438 == (char *)0x0) break;
                                      iVar9 = _inet_addr(pcStack_10438);
                                      *(in_addr_t *)
                                       (*(long *)(puStack_10340 + 0x46cc) + (long)iStack_1042c * 4)
                                           = iVar9;
                                      iStack_1042c = iStack_1042c + 1;
                                      pcStack_10438 = _strtok((char *)0x0,";");
                                    } while (iStack_1042c != 0x10);
                                  }
                                  if (0 < iStack_1042c) {
                                    puStack_10340[0x46ca] = iStack_1042c;
                                  }
                                  for (uStack_10444 = 0; uStack_10444 < (uint)puStack_10340[0x46ca];
                                      uStack_10444 = uStack_10444 + 1) {
                                    if (_array_vpn_log_level_ < 2) {
                                      _array_vpn_logprint(1,"get_config.c",0x8ba,
                                                          "dns config: index[%d], %d.%d.%d.%d.\n",
                                                          uStack_10444,
                                                          *(undefined1 *)
                                                           (*(long *)(puStack_10340 + 0x46cc) +
                                                           (long)(int)uStack_10444 * 4),
                                                          *(undefined1 *)
                                                           (*(long *)(puStack_10340 + 0x46cc) + 1 +
                                                           (long)(int)uStack_10444 * 4),
                                                          *(undefined1 *)
                                                           (*(long *)(puStack_10340 + 0x46cc) + 2 +
                                                           (long)(int)uStack_10444 * 4),
                                                          *(undefined1 *)
                                                           (*(long *)(puStack_10340 + 0x46cc) + 3 +
                                                           (long)(int)uStack_10444 * 4));
                                    }
                                  }
                                  iStack_10348 = 0;
                                }
                              }
                              else {
                                if (_array_vpn_log_level_ < 4) {
                                  _array_vpn_logprint(3,"get_config.c",0x7dc,
                                                                                                            
                                                  "get_ag_config: invalid network config response, msg type: %d\n"
                                                  ,acStack_10370[0]);
                                }
                                iStack_10348 = 0x28;
                              }
                            }
                          }
                          else {
                            puStack_10340[0x15] = 0x29;
                            iStack_10348 = 0x29;
                          }
                        }
                      }
                      else {
                        puStack_10340[0x15] = 0x29;
                        iStack_10348 = 0x29;
                      }
                    }
                  }
                  else {
                    if (_array_vpn_log_level_ < 4) {
                      _array_vpn_logprint(3,"get_config.c",0x6d8,
                                          "get_ag_config: invalid common config response, msg type: %d\n"
                                          ,acStack_10370[0]);
                    }
                    iStack_10348 = 0x28;
                  }
                }
              }
              else {
                puStack_10340[0x15] = 0x29;
                iStack_10348 = 0x29;
              }
            }
          }
          else {
            puStack_10340[0x15] = 0x29;
            iStack_10348 = 0x29;
          }
        }
      }
      else if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"get_config.c",0x6a6,
                            "get_ag_config: failed to recv response from ag\n");
      }
    }
  }
  else {
    puStack_10340[0x15] = 0x29;
    iStack_10348 = 0x29;
  }
LAB_00059ba5:
  if (puStack_10420 != (undefined4 *)0x0) {
    _free(puStack_10420);
  }
  if (lStack_10408 != 0) {
    _cJSON_Delete(lStack_10408);
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 == lVar1) {
    return iStack_10348;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

 (GhidraScript)  
===== handle_ssl_tunnel @ 00061b10 ===== (GhidraScript)  
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int _handle_ssl_tunnel(long param_1,int param_2)

{
  ushort uVar1;
  __uint16_t _Var2;
  int iVar3;
  undefined4 uVar4;
  uint local_168;
  uint local_164;
  int local_14c;
  char local_148 [144];
  char local_b8 [136];
  long local_30;
  
  local_30 = *(long *)PTR____stack_chk_guard_002e4060;
  if (param_2 != 0) {
    _handle_ssl_tunnel_offset = 0;
  }
  iVar3 = _SSL_read(*(undefined8 *)(param_1 + 0x38),
                    &_handle_ssl_tunnel_buf + (int)(uint)_handle_ssl_tunnel_offset,
                    0x10000 - (uint)_handle_ssl_tunnel_offset);
  if (*(int *)(param_1 + 0x50) == 0) {
    if (iVar3 < 1) {
      uVar4 = _SSL_get_error(*(undefined8 *)(param_1 + 0x38),iVar3);
      if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"l3vpn.c",0x5bb,
                            "handle ssl tunnel, SSL read failed, error %d, SSL error %d.\n",iVar3,
                            uVar4);
      }
      _handle_ssl_tunnel_offset = 0;
      local_14c = 2;
    }
    else {
      __g_reconnectManually = 0;
      if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
        _array_vpn_logprint(1,"l3vpn.c",0x5c2,"handel ssl tunnel, recv %d bytes\n",iVar3);
      }
      _stat_recv_add((long)iVar3);
      _handle_ssl_tunnel_offset = _handle_ssl_tunnel_offset + (short)iVar3;
      if (_handle_ssl_tunnel_offset < 0x14) {
        if (_array_vpn_log_level_ < 4) {
          _array_vpn_logprint(3,"l3vpn.c",0x5c9,"recv bytes (%d) < ipheader size\n",
                              _handle_ssl_tunnel_offset);
        }
        local_14c = 0;
      }
      else {
        if (_handle_ssl_tunnel_buf >> 4 == 6) {
          _Var2 = __OSSwapInt16(DAT_0072c374);
          uVar1 = _handle_ssl_tunnel_offset;
          if ((uint)_handle_ssl_tunnel_offset < _Var2 + 0x28) {
            if (_array_vpn_log_level_ < 4) {
              _Var2 = __OSSwapInt16(DAT_0072c374);
              _array_vpn_logprint(3,"l3vpn.c",0x5cf,"recv bytes (%d) < ip6 packet size(%d)\n",uVar1,
                                  _Var2 + 0x28);
            }
            local_14c = 0;
            goto LAB_000623c6;
          }
        }
        else {
          _Var2 = __OSSwapInt16(DAT_0072c372);
          uVar1 = _handle_ssl_tunnel_offset;
          if (_handle_ssl_tunnel_offset < _Var2) {
            if (_array_vpn_log_level_ < 4) {
              _Var2 = __OSSwapInt16(DAT_0072c372);
              _array_vpn_logprint(3,"l3vpn.c",0x5d4,"recv bytes (%d) < ip packet size(%d)\n",uVar1,
                                  _Var2);
            }
            local_14c = 0;
            goto LAB_000623c6;
          }
        }
        local_164 = 0;
        while ((int)local_164 < (int)(uint)_handle_ssl_tunnel_offset) {
          if ((&_handle_ssl_tunnel_buf)[(int)local_164] >> 4 == 6) {
            _Var2 = __OSSwapInt16(*(__uint16_t *)((long)&DAT_0072c374 + (long)(int)local_164));
            local_168 = _Var2 + 0x28;
          }
          else {
            _Var2 = __OSSwapInt16(*(__uint16_t *)((long)&DAT_0072c372 + (long)(int)local_164));
            local_168 = (uint)_Var2;
          }
          if (local_168 == 0) {
            if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
              _array_vpn_logprint(1,"l3vpn.c",0x5e5,
                                  "leave partial ip packet: index:%d, offset:%d, new_offser:%d\n",
                                  local_164,_handle_ssl_tunnel_offset,
                                  _handle_ssl_tunnel_offset - local_164);
            }
            ___memmove_chk(&_handle_ssl_tunnel_buf,&_handle_ssl_tunnel_buf + (int)local_164,
                           (long)(int)(_handle_ssl_tunnel_offset - local_164),0x10000);
            _handle_ssl_tunnel_offset = _handle_ssl_tunnel_offset - (short)local_164;
            local_14c = 0;
            goto LAB_000623c6;
          }
          if ((int)(uint)_handle_ssl_tunnel_offset < (int)(local_164 + local_168)) {
            if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
              _array_vpn_logprint(1,"l3vpn.c",0x5ee,
                                  "leave partial ip packet: index:%d, offset:%d, new_offser:%d\n",
                                  local_164,_handle_ssl_tunnel_offset,
                                  _handle_ssl_tunnel_offset - local_164);
            }
            ___memmove_chk(&_handle_ssl_tunnel_buf,&_handle_ssl_tunnel_buf + (int)local_164,
                           (long)(int)(_handle_ssl_tunnel_offset - local_164),0x10000);
            _handle_ssl_tunnel_offset = _handle_ssl_tunnel_offset - (short)local_164;
            local_14c = 0;
            goto LAB_000623c6;
          }
          if ((&DAT_0072c379)[(int)local_164] == -1) {
            local_14c = _handle_atp_packets(param_1,&_handle_ssl_tunnel_buf + (int)local_164,0);
            if (local_14c != 0) goto LAB_000623c6;
            local_164 = local_168 + local_164;
          }
          else {
            if ((&_handle_ssl_tunnel_buf)[(int)local_164] >> 4 == 6) {
              _inet_ntop(0x1e,(void *)((long)(int)local_164 + 0x72c378),local_b8,0x88);
              _inet_ntop(0x1e,(void *)((long)(int)local_164 + 0x72c388),local_148,0x88);
              if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
                _array_vpn_logprint(1,"l3vpn.c",0x605,
                                    "read %d ipv6 bytes from ssl tunnel, %s --> %s\n",local_168,
                                    local_b8,local_148);
              }
            }
            else if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
              _array_vpn_logprint(1,"l3vpn.c",0x60b,
                                  "read %d ipv4 bytes from ssl tunnel, %d.%d.%d.%d --> %d.%d.%d.%d\n"
                                  ,local_168,(&DAT_0072c37c)[(int)local_164],
                                  (&DAT_0072c37d)[(int)local_164],(&DAT_0072c37e)[(int)local_164],
                                  (&DAT_0072c37f)[(int)local_164],(&DAT_0072c380)[(int)local_164],
                                  (&DAT_0072c381)[(int)local_164],(&DAT_0072c382)[(int)local_164],
                                  (&DAT_0072c383)[(int)local_164]);
            }
            iVar3 = _write_to_vnic(param_1,&_handle_ssl_tunnel_buf + (int)local_164,local_168);
            if (iVar3 < 1) {
              _handle_ssl_tunnel_offset = 0;
              local_14c = 1;
              goto LAB_000623c6;
            }
            local_164 = local_168 + local_164;
          }
        }
        if (local_164 == _handle_ssl_tunnel_offset) {
          _handle_ssl_tunnel_offset = 0;
        }
        local_14c = 0;
      }
    }
  }
  else {
    *(undefined4 *)(param_1 + 0x54) = 0x29;
    local_14c = 0x29;
  }
LAB_000623c6:
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_30) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return local_14c;
}

 (GhidraScript)  
===== send_tcp_tunnel_keep_alive @ 00062b30 ===== (GhidraScript)  
undefined4 _send_tcp_tunnel_keep_alive(long param_1,int param_2)

{
  int iVar1;
  undefined4 local_2c;
  undefined8 local_28;
  undefined8 local_20;
  undefined4 local_18;
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  local_28 = DAT_0026c3d8;
  local_20 = DAT_0026c3e0;
  local_18 = DAT_0026c3e8;
  if (0 < param_2) {
    local_20 = CONCAT26((short)param_2,(int6)DAT_0026c3e0);
  }
  iVar1 = _SSL_write(*(undefined8 *)(param_1 + 0x38),&local_28,0x14);
  if (*(int *)(param_1 + 0x50) == 0) {
    if (iVar1 < 1) {
      if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"l3vpn.c",0x740,"send tcp tunnel keep alive failed.\n");
      }
      local_2c = 3;
    }
    else {
      _stat_send_add(0x14);
      local_2c = 0;
    }
  }
  else {
    *(undefined4 *)(param_1 + 0x54) = 0x29;
    local_2c = 0x29;
  }
  if (*(long *)PTR____stack_chk_guard_002e4060 == local_10) {
    return local_2c;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

 (GhidraScript)  
===== send_keep_alive @ 00062dd0 ===== (GhidraScript)  
undefined8 _send_keep_alive(undefined8 param_1)

{
  _send_tcp_tunnel_keep_alive(param_1,0);
  _send_udp_tunnel_keep_alive(param_1,0);
  return 1;
}

 (GhidraScript)  
===== get_l3vpn_config @ 00064870 ===== (GhidraScript)  
undefined8 _get_l3vpn_config(long *param_1)

{
  int iVar1;
  void *pvVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int local_48;
  uint local_44;
  long local_40;
  
  local_48 = DAT_00709b30 * 0x20 + 0x380;
  if (DAT_007092f8 == '\0') {
    local_48 = DAT_00709300 * 0x40 + local_48;
  }
  pvVar2 = _calloc((long)local_48,1);
  *param_1 = (long)pvVar2;
  local_40 = *param_1;
  uVar3 = (uint)DAT_0070915b;
  uVar4 = (uint)DAT_00709158;
  uVar6 = (uint)DAT_00709159;
  uVar5 = (uint)DAT_0070915a;
  iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,
                         "Assigned IP:%d.%d.%d.%d/%d.%d.%d.%d/%d.%d.%d.%d\n",DAT_00709150,
                         DAT_00709151,DAT_00709152,DAT_00709153,DAT_00709154,DAT_00709155,
                         DAT_00709156,DAT_00709157,uVar4,uVar6,uVar5,uVar3);
  local_40 = local_40 + iVar1;
  if (DAT_007092f8 == '\0') {
    iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"Zone List:");
    local_40 = local_40 + iVar1;
    for (local_44 = 0; local_44 < DAT_00709300; local_44 = local_44 + 1) {
      iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"%d.%d.%d.%d/%d.%d.%d.%d",
                             *(undefined1 *)(DAT_00709308 + (ulong)local_44 * 0x10c),
                             *(undefined1 *)(DAT_00709308 + (ulong)local_44 * 0x10c + 1),
                             *(undefined1 *)(DAT_00709308 + (ulong)local_44 * 0x10c + 2),
                             *(undefined1 *)(DAT_00709308 + (ulong)local_44 * 0x10c + 3),
                             *(undefined1 *)(DAT_00709308 + (ulong)local_44 * 0x10c + 4),
                             *(undefined1 *)(DAT_00709308 + (ulong)local_44 * 0x10c + 5),
                             *(undefined1 *)(DAT_00709308 + (ulong)local_44 * 0x10c + 6),
                             *(undefined1 *)(DAT_00709308 + (ulong)local_44 * 0x10c + 7),uVar4,uVar6
                             ,uVar5,uVar3);
      local_40 = local_40 + iVar1;
      if (local_44 == DAT_00709300 - 1) {
        iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"\n");
      }
      else {
        iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,",");
      }
      local_40 = local_40 + iVar1;
    }
  }
  else {
    iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"Zone List: 0.0.0.0/0.0.0.0\n");
    local_40 = local_40 + iVar1;
  }
  iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"DNS Server:");
  local_40 = local_40 + iVar1;
  if (DAT_00709b30 == 0) {
    iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"\n");
    local_40 = local_40 + iVar1;
  }
  else {
    for (local_44 = 0; local_44 < DAT_00709b30; local_44 = local_44 + 1) {
      if (local_44 == DAT_00709b30 - 1) {
        iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"%d.%d.%d.%d\n",
                               *(undefined1 *)(DAT_00709b38 + (ulong)local_44 * 4),
                               *(undefined1 *)(DAT_00709b38 + 1 + (ulong)local_44 * 4),
                               *(undefined1 *)(DAT_00709b38 + 2 + (ulong)local_44 * 4),
                               *(undefined1 *)(DAT_00709b38 + 3 + (ulong)local_44 * 4));
      }
      else {
        iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"%d.%d.%d.%d,",
                               *(undefined1 *)(DAT_00709b38 + (ulong)local_44 * 4),
                               *(undefined1 *)(DAT_00709b38 + 1 + (ulong)local_44 * 4),
                               *(undefined1 *)(DAT_00709b38 + 2 + (ulong)local_44 * 4),
                               *(undefined1 *)(DAT_00709b38 + 3 + (ulong)local_44 * 4));
      }
      local_40 = local_40 + iVar1;
    }
  }
  if (DAT_00709b60 != (char *)0x0) {
    if (*DAT_00709b60 == '\0') {
      iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"Search Domain:\n");
    }
    else {
      iVar1 = ___sprintf_chk(local_40,0,0xffffffffffffffff,"Search Domain:%s\n",DAT_00709b60);
    }
    local_40 = local_40 + iVar1;
  }
  if (DAT_0070b108 == 0) {
    ___sprintf_chk(local_40,0,0xffffffffffffffff,"Tunnel Socket:%d\n",_l3vpn_data);
  }
  else {
    ___sprintf_chk(local_40,0,0xffffffffffffffff,"Tunnel Socket:%d,%d\n",_l3vpn_data,DAT_00708b10);
  }
  return 0;
}

 (GhidraScript)  
===== array_vpn_logout @ 0006cb60 ===== (GhidraScript)  
int _array_vpn_logout(void)

{
  int local_c;
  
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"l3vpn.c",&DAT_000011e2,"array_vpn_logout: enter");
  }
  if (DAT_0069bcb4 == '\0') {
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"l3vpn.c",&DAT_000011e4,"session is invalid, do not need logout\n");
    }
    local_c = 6;
  }
  else {
    DAT_0069bc50 = 0;
    DAT_0069bc48 = 0;
    DAT_0069bc60 = (EVP_PKEY *)0x0;
    DAT_0069bc58 = (X509 *)0x0;
    _current_session = -1;
    DAT_0069bc68 = 0;
    _parse_session_cert_file(&_current_session);
    local_c = _logout_vpn_server(&_current_session);
    if (DAT_0069bc50 != 0) {
      _SSL_free(DAT_0069bc50);
    }
    if (DAT_0069bc48 != 0) {
      _SSL_CTX_free(DAT_0069bc48);
    }
    if (DAT_0069bc60 != (EVP_PKEY *)0x0) {
      _EVP_PKEY_free(DAT_0069bc60);
    }
    if (DAT_0069bc58 != (X509 *)0x0) {
      _X509_free(DAT_0069bc58);
    }
    DAT_0069bc50 = 0;
    DAT_0069bc48 = 0;
    DAT_0069bc60 = (EVP_PKEY *)0x0;
    DAT_0069bc58 = (X509 *)0x0;
    if ((_current_session != 0) && (_current_session != -1)) {
      _close(_current_session);
    }
    _current_session = 0xffffffff;
    _array_clear_spa_info();
    if (local_c == 0) {
      _memset(&_current_session,0,0x10b08);
    }
    if (_array_vpn_log_level_ < 1) {
      _array_vpn_logprint(0,"l3vpn.c",&DAT_00001201,"array_vpn_logout: end");
    }
  }
  return local_c;
}

 (GhidraScript)  
===== array_send_keep_alive @ 000755c0 ===== (GhidraScript)  
void _array_send_keep_alive(void)

{
  return;
}

 (GhidraScript)  
===== open_dtls_tunnel @ 0009c5b0 ===== (GhidraScript)  
/* WARNING: Removing unreachable block (ram,0x0009cd77) */
/* WARNING: Removing unreachable block (ram,0x0009ce19) */
/* WARNING: Removing unreachable block (ram,0x0009ce26) */
/* WARNING: Removing unreachable block (ram,0x0009ce4c) */
/* WARNING: Removing unreachable block (ram,0x0009ce5b) */
/* WARNING: Removing unreachable block (ram,0x0009ce74) */
/* WARNING: Removing unreachable block (ram,0x0009ce81) */
/* WARNING: Removing unreachable block (ram,0x0009ce95) */
/* WARNING: Removing unreachable block (ram,0x0009ceb4) */
/* WARNING: Removing unreachable block (ram,0x0009ceb9) */

undefined8 _open_dtls_tunnel(undefined8 param_1)

{
  __uint16_t _Var1;
  int iVar2;
  int *piVar3;
  BIO *bp;
  undefined8 uVar4;
  char *pcVar5;
  undefined4 uVar6;
  sockaddr *local_738;
  long local_728;
  long local_720;
  socklen_t local_714;
  int local_710;
  int local_70c;
  size_t local_708;
  undefined8 local_700;
  sockaddr local_6b8 [8];
  char local_638 [1499];
  undefined1 local_5d;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  local_700 = param_1;
  _memset(local_58,0,0x40);
  local_710 = 0xffffffff;
  local_720 = 0;
  local_728 = 0;
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"udp_tunnel.c",0x188,"open dtls tunnel, begin\n");
  }
  DAT_00709138 = 1;
  DAT_00708b1c = 1;
  if (DAT_006f800c._4_4_ == 0) {
    local_710 = _socket(0x1e,2,0x11);
    DAT_00708b34 = DAT_006f801c;
    DAT_00708b3c = DAT_006f8024;
    DAT_00708b44 = DAT_006f802c;
    DAT_00708b4c = DAT_006f8034;
    _Var1 = __OSSwapInt16(DAT_00708b20);
    DAT_00708b34._0_4_ = CONCAT22(_Var1,(undefined2)DAT_00708b34);
    local_738 = (sockaddr *)&DAT_00708b34;
    local_714 = 0x1c;
  }
  else {
    local_710 = _socket(2,2,0x11);
    DAT_00708b24 = CONCAT44(DAT_006f800c._4_4_,(undefined4)DAT_006f800c);
    DAT_00708b2c = DAT_006f8014;
    _Var1 = __OSSwapInt16(DAT_00708b20);
    DAT_00708b24._0_4_ = CONCAT22(_Var1,(undefined2)DAT_00708b24);
    local_738 = (sockaddr *)&DAT_00708b24;
    local_714 = 0x10;
  }
  if (local_710 < 0) {
    if (_array_vpn_log_level_ < 4) {
      _array_vpn_logprint(3,"udp_tunnel.c",0x19b,"open dtls tunnel: failed to create socket\n");
    }
  }
  else {
    uVar6 = 0;
    _vpncallback(&_l3vpn_data,0x18,0,(long)local_710,0,0,0);
    local_70c = _connect(local_710,local_738,local_714);
    if (local_70c == 0) {
      bp = _BIO_new_dgram(local_710,0);
      local_714 = 0x80;
      ___memset_chk(local_6b8,0,0x80,0x80);
      iVar2 = _getsockname(local_710,local_6b8,&local_714);
      if (iVar2 < 0) {
        _printf("getsockname error\n");
        if (_array_vpn_log_level_ < 4) {
          piVar3 = ___error();
          _array_vpn_logprint(3,"udp_tunnel.c",0x1ac,
                              "open dtls tunnel: get socket local address failed, os error: %d\n",
                              *piVar3);
        }
      }
      else {
        _BIO_ctrl(bp,0x2c,0,local_6b8);
        _BIO_ctrl(bp,0x20,0,local_6b8);
        uVar4 = _DTLSv1_client_method();
        local_720 = _SSL_CTX_new(uVar4);
        if (local_720 == 0) {
          if (_array_vpn_log_level_ < 4) {
            piVar3 = ___error();
            _array_vpn_logprint(3,"udp_tunnel.c",0x1b4,
                                "open dtls tunnel: create dtls ctx failed, os error: %d\n",*piVar3);
          }
        }
        else {
          local_728 = _SSL_new(local_720);
          _SSL_CTX_ctrl(local_720,0x29,1,0);
          _SSL_set_options(local_728,0x1000);
          _SSL_ctrl(local_728,0x11,DAT_0070b118,0);
          _SSL_ctrl(local_728,0x78,DAT_0070b118,0);
          _SSL_ctrl(local_728,0x21,4,0);
          _SSL_set_bio(local_728,bp,bp);
          _SSL_set_connect_state(local_728);
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"udp_tunnel.c",0x1c5,"open dtls tunnel: do ssl handshake\n");
          }
          iVar2 = _SSL_connect(local_728);
          if (iVar2 < 0) {
            if (_array_vpn_log_level_ < 4) {
              piVar3 = ___error();
              _array_vpn_logprint(3,"udp_tunnel.c",0x1c7,
                                  "open dtls tunnel: failed to do ssl handshake, os error: %d\n",
                                  *piVar3);
            }
          }
          else {
            ___snprintf_chk(local_58,0x40,0,0x40,"%s%d%d",&DAT_006fde38,CONCAT44(uVar6,DAT_00708b1c)
                            ,DAT_00709130);
            local_708 = _strlen(local_58);
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"udp_tunnel.c",0x1cd,"open dtls tunnel: request is [%s]\n",
                                  local_58);
            }
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"udp_tunnel.c",0x1cf,"open dtls tunnel: send open request\n");
            }
            local_70c = _SSL_write(local_728,local_58,local_708 & 0xffffffff);
            if ((long)local_70c == local_708) {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"udp_tunnel.c",0x1d6,"open dtls tunnel: read open response\n")
                ;
              }
              local_70c = _SSL_read(local_728,local_638,local_708 & 0xffffffff);
              if (local_70c < 1) {
                if (_array_vpn_log_level_ < 4) {
                  piVar3 = ___error();
                  _array_vpn_logprint(3,"udp_tunnel.c",0x1d9,
                                      "open dtls tunnel: failed to read esponse, os error: %d\n",
                                      *piVar3);
                }
              }
              else {
                pcVar5 = _strnstr(local_638,"200 OK",0x5db);
                if (pcVar5 != (char *)0x0) {
                  DAT_00708b10 = local_710;
                  DAT_0070b108 = 1;
                  DAT_00709140 = local_720;
                  DAT_00709148 = local_728;
                  _SetWinTUNUDPRunning(1);
                  _set_udp_tunnel_running_status(1);
                  _SetKeepaliveSettings(2,1,0);
                  _send_keep_alive(&_l3vpn_data);
                  if (_array_vpn_log_level_ < 2) {
                    _array_vpn_logprint(1,"udp_tunnel.c",0x203,
                                        "open dtls tunnel: dtls tunnel is ready now\n");
                  }
                  goto LAB_0009d03f;
                }
                local_5d = 0;
                if (_array_vpn_log_level_ < 4) {
                  _array_vpn_logprint(3,"udp_tunnel.c",0x1de,
                                      "open dtls tunnel: response is invalid, response: %s\n",
                                      local_638);
                }
              }
            }
            else if (_array_vpn_log_level_ < 4) {
              piVar3 = ___error();
              _array_vpn_logprint(3,"udp_tunnel.c",0x1d2,
                                  "open dtls tunnel: failed to write open request, os error: %d\n",
                                  *piVar3);
            }
          }
        }
      }
    }
    else if (_array_vpn_log_level_ < 4) {
      piVar3 = ___error();
      _array_vpn_logprint(3,"udp_tunnel.c",0x1a3,
                          "open dtls tunnel: failed to connect, os error: %d\n",*piVar3);
    }
  }
  _set_udp_tunnel_running_status(0);
  _switch_tunnel(&_l3vpn_data);
  if (_array_vpn_log_level_ < 4) {
    _array_vpn_logprint(3,"udp_tunnel.c",0x20a,"open dtls tunnel: failed to establish dtls tunnel\n"
                       );
  }
  if (local_728 != 0) {
    _SSL_free(local_728);
  }
  if (local_720 != 0) {
    _SSL_CTX_free(local_720);
  }
  if (((0 < local_710) && (local_710 != 0)) && (local_710 != -1)) {
    _close(local_710);
  }
LAB_0009d03f:
  _thrd_detach(_speed_tunnel_open_thread);
  _thrd_set_null(&_speed_tunnel_open_thread);
  if (*(long *)PTR____stack_chk_guard_002e4060 == local_10) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}

 (GhidraScript)  
