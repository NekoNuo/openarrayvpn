===== do_normal_login @ 0000c960 ===== (GhidraScript)  
int _do_normal_login(long param_1,int *param_2,undefined4 *param_3)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  size_t sVar4;
  undefined8 in_stack_fffffffffffd1108;
  undefined8 uVar5;
  int *piVar6;
  undefined4 uVar7;
  undefined4 uStack_2eec8;
  undefined4 uStack_2eec4;
  uint uStack_2eec0;
  uint uStack_2eebc;
  int iStack_2eeb8;
  int iStack_2eeb4;
  long lStack_2eeb0;
  int iStack_2eea4;
  long lStack_2eea0;
  uint uStack_2ee94;
  char *pcStack_2ee90;
  void *pvStack_2ee88;
  undefined4 uStack_2ee80;
  int iStack_2ee7c;
  undefined4 *puStack_2ee78;
  int *piStack_2ee70;
  long lStack_2ee68;
  int iStack_2ee5c;
  undefined1 auStack_2ee58 [16];
  undefined4 uStack_2ee48;
  char acStack_1ddf6 [2689];
  char acStack_1d375 [18701];
  char acStack_18a68 [65536];
  undefined1 local_8a68 [35344];
  char local_58 [72];
  long local_10;
  
  uVar7 = (undefined4)((ulong)in_stack_fffffffffffd1108 >> 0x20);
  local_10 = *(long *)PTR____stack_chk_guard_002e4060;
  puStack_2ee78 = param_3;
  piStack_2ee70 = param_2;
  lStack_2ee68 = param_1;
  _memset(local_58,0,0x40);
  pvStack_2ee88 = (void *)0x0;
  pcStack_2ee90 = (char *)0x0;
  lStack_2eea0 = 0;
  *piStack_2ee70 = 0;
  if (piStack_2ee70[0xc] == 0) {
    piStack_2ee70[0xe] = 0;
    piStack_2ee70[0xf] = 0;
    piStack_2ee70[0x10] = 0;
    piStack_2ee70[0x11] = 0;
  }
  else if (piStack_2ee70[0xc] == 1) {
    uVar1 = _get_current_time();
    *(ulong *)(piStack_2ee70 + 0xe) = (ulong)uVar1;
    uVar1 = _get_current_time();
    *(ulong *)(piStack_2ee70 + 0x10) = (ulong)uVar1;
  }
  else {
    uVar1 = _get_current_time();
    *(ulong *)(piStack_2ee70 + 0x10) = (ulong)uVar1;
  }
  lStack_2eeb0 = *(long *)(piStack_2ee70 + 0x10) - *(long *)(piStack_2ee70 + 0xe);
  if (_array_vpn_log_level_ < 2) {
    uVar5 = CONCAT44(uVar7,(uint)*(byte *)(lStack_2ee68 + 0xbbba));
    _array_vpn_logprint(1,"aaa.c",0x786,
                        "do normal login: ctx->do_callback:%d, ctx->loopnum:%d, stop_flag:%d, interval:%d"
                        ,piStack_2ee70[8],piStack_2ee70[0xc],uVar5,lStack_2eeb0);
    uVar7 = (undefined4)((ulong)uVar5 >> 0x20);
  }
  if ((*(char *)(lStack_2ee68 + 0xbbba) == '\x01') || (*(int *)(lStack_2ee68 + 0x50) == 1)) {
    if (_array_vpn_log_level_ < 3) {
      _array_vpn_logprint(2,"aaa.c",0x789,"do_normal_login: but qr_stop_flag is 1, exit\n");
    }
    _vpncallback(lStack_2ee68,0xcb,0,0,0,0,0);
    iStack_2ee7c = 0x85;
    *puStack_2ee78 = 0;
    iStack_2ee5c = 0x85;
  }
  else if (*(char *)(lStack_2ee68 + 0xbbba) == '\x02') {
    if (_array_vpn_log_level_ < 3) {
      _array_vpn_logprint(2,"aaa.c",0x792,"do_normal_login: user switch qrcode to normal\n");
    }
    *(undefined1 *)(lStack_2ee68 + 0xbbba) = 0;
    *piStack_2ee70 = 10;
    iStack_2ee7c = 0;
    iStack_2ee5c = 0;
  }
  else {
    if (599999 < lStack_2eeb0) {
      piStack_2ee70[0xc] = 9999;
    }
    if (piStack_2ee70[8] == 0) {
      piStack_2ee70[8] = 1;
    }
    else {
      iStack_2eeb4 = 0x8a0b;
      ___memset_chk(local_8a68,0,0x8a0b,0x8a0b);
      piVar6 = &iStack_2eeb4;
      iStack_2ee7c = _vpncallback(lStack_2ee68,0xd,0,*(undefined8 *)(piStack_2ee70 + 10),0x163ea,
                                  local_8a68,piVar6);
      uVar7 = (undefined4)((ulong)piVar6 >> 0x20);
      if ((iStack_2ee7c != 0) || (iStack_2eeb4 == 0)) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x7a8,"login callback isn\'t prcessed by upper layer.\n");
        }
        iStack_2ee7c = 0x3c;
        iStack_2ee5c = 0x3c;
        goto LAB_0000dbe5;
      }
      _copy_auth_input(lStack_2ee68,local_8a68);
    }
    lStack_2eea0 = _choose_method(&UNK_00001300 + lStack_2ee68,*(undefined8 *)(piStack_2ee70 + 10));
    if ((lStack_2eea0 == 0) && (*(char *)(*(long *)(piStack_2ee70 + 10) + 7) == '\0')) {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x7b4,"do normal login: choose methods failed\n");
      }
      iStack_2ee7c = 0x34;
      iStack_2ee5c = 0x34;
    }
    else {
      if (lStack_2eea0 == 0) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x7be,"do normal login: method is NULL, maybe rand is on.\n"
                             );
        }
      }
      else if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x7ba,
                            "choose_method finished, the method->type is %d(AUTH_THIRDPARTY:15, AUTH_QRCODE:13, AUTH_PHONESMS:14, HTTP:10)\n"
                            ,*(undefined4 *)(lStack_2eea0 + 0x804));
      }
      iStack_2eeb8 = 0;
      if (((lStack_2eea0 != 0) &&
          (((pcVar3 = _strstr((char *)(lStack_2eea0 + 0x201),"qrcode"), pcVar3 != (char *)0x0 ||
            (pcVar3 = _strstr((char *)(lStack_2eea0 + 0x201),"QRcode"), pcVar3 != (char *)0x0)) ||
           (pcVar3 = _strstr((char *)(lStack_2eea0 + 0x201),"Qrcode"), pcVar3 != (char *)0x0)))) &&
         (*(int *)(lStack_2eea0 + 0x804) == 10)) {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x7c5,"choose method finished, method_desc:%s, type:%d\n",
                              lStack_2eea0 + 0x201,*(undefined4 *)(lStack_2eea0 + 0x804));
        }
        iStack_2eeb8 = 1;
        piStack_2ee70[8] = 0;
      }
      *(long *)(piStack_2ee70 + 6) = lStack_2eea0;
      if (pvStack_2ee88 != (void *)0x0) {
        _free(pvStack_2ee88);
      }
      pvStack_2ee88 = (void *)0x0;
      iStack_2ee7c = _build_login_req(lStack_2ee68,lStack_2eea0,0,&pvStack_2ee88,
                                      *(undefined8 *)(piStack_2ee70 + 10));
      if (iStack_2ee7c == 0) {
        if ((lStack_2eea0 != 0) &&
           ((*(int *)(lStack_2eea0 + 0x804) == 0xf || (*(int *)(lStack_2eea0 + 0x804) == 0xd)))) {
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"aaa.c",0x7d4,
                                "do normal login, cycle test results required......this is qrcode aaa or third aaa\n"
                               );
          }
          iStack_2eeb8 = 1;
          piStack_2ee70[8] = 0;
        }
        if (pcStack_2ee90 != (char *)0x0) {
          _free(pcStack_2ee90);
        }
        pcStack_2ee90 = (char *)0x0;
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x7db,"mauth_username:%s.\n",lStack_2ee68 + 0xf5f4);
        }
        sVar4 = _strlen((char *)(lStack_2ee68 + 0xf5f4));
        if (sVar4 != 0) {
          _memset(acStack_18a68,0,0x10000);
          pcStack_2ee90 = _malloc(0x10000);
          uVar5 = CONCAT44(uVar7,0x10000);
          iStack_2ee7c = _mauth_download(lStack_2ee68 + 0x9c,*(undefined4 *)(lStack_2ee68 + 0x29c),
                                         pvStack_2ee88,"sm2",lStack_2ee68 + 0xf7f8,acStack_18a68,
                                         uVar5);
          pcVar3 = pcStack_2ee90;
          uVar7 = (undefined4)((ulong)uVar5 >> 0x20);
          if (iStack_2ee7c == 0) {
            sVar4 = _strlen(acStack_18a68);
            ___memcpy_chk(pcVar3,acStack_18a68,sVar4,0xffffffffffffffff);
          }
          else {
            _mauth_free(0);
            ___memset_chk(lStack_2ee68 + 0xf5f4,0,0x100,0xffffffffffffffff);
          }
        }
        sVar4 = _strlen((char *)(lStack_2ee68 + 0xf5f4));
        if (sVar4 == 0) {
          iStack_2ee7c = _ssl_get_page_auto_malloc
                                   (lStack_2ee68,pvStack_2ee88,&pcStack_2ee90,&uStack_2ee94);
        }
        if (iStack_2ee7c == 0) {
          if ((_g_printlogtraffic != 0) && (_array_vpn_log_level_ < 2)) {
            _array_vpn_logprint(1,"aaa.c",0x812,"response buffer:\n%s\n",pcStack_2ee90);
          }
          iVar2 = _is_http_redirect(pcStack_2ee90);
          piStack_2ee70[4] = iVar2;
          uStack_2ee80 = 0x3f;
          iVar2 = _get_page_location(pcStack_2ee90,local_58,&uStack_2ee80);
          if (iVar2 != 0) {
            _memset(auStack_2ee58,0,0x163ea);
            iStack_2ee7c = _get_aaa_method_info(pcStack_2ee90,auStack_2ee58);
            if (iStack_2ee7c == 0) {
              iStack_2ee7c = _convert_aaa_error(uStack_2ee48);
              *(undefined4 *)(*(long *)(piStack_2ee70 + 10) + 0x10) = uStack_2ee48;
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"aaa.c",0x822,"do normal login failed, parse error id=%d.\n",
                                    *(undefined4 *)(*(long *)(piStack_2ee70 + 10) + 0x10));
              }
            }
            else {
              iStack_2ee7c = 0x25;
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"aaa.c",0x81e,"do normal login failed, wrong password.\n");
              }
            }
            sVar4 = _strlen(acStack_1ddf6);
            if ((sVar4 == 0) && (sVar4 = _strlen(acStack_1d375), sVar4 != 0)) {
              sVar4 = _strlen(acStack_1d375);
              uStack_2eebc = (uint)sVar4;
              if (uStack_2eebc < 0x800) {
                ___strncpy_chk(*(long *)(piStack_2ee70 + 10) + 0x11062,acStack_1d375,
                               sVar4 & 0xffffffff,0x800);
              }
              else {
                ___strncpy_chk(*(long *)(piStack_2ee70 + 10) + 0x11062,acStack_1d375,0x7ff,0x800);
              }
            }
            else {
              sVar4 = _strlen(acStack_1ddf6);
              uStack_2eec0 = (uint)sVar4;
              ___memset_chk(*(long *)(piStack_2ee70 + 10) + 0x11062,0,0x800,0xffffffffffffffff);
              if (uStack_2eec0 < 0x800) {
                ___strncpy_chk(*(long *)(piStack_2ee70 + 10) + 0x11062,acStack_1ddf6,uStack_2eec0,
                               0x800);
              }
              else {
                ___strncpy_chk(*(long *)(piStack_2ee70 + 10) + 0x11062,acStack_1ddf6,0x7ff,0x800);
              }
            }
            iVar2 = iStack_2ee7c;
            if (0x4000 < uStack_2ee94) {
              pcStack_2ee90[0x4000] = '\0';
            }
            _g_print_login_loop_log = _g_print_login_loop_log + 1;
            if (_g_print_login_loop_log < 3) {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"aaa.c",0x83f,
                                    "do normal login failed, location not found, error %d, buf:\n[%s]\n"
                                    ,iStack_2ee7c,pcStack_2ee90);
              }
            }
            else if (_array_vpn_log_level_ < 2) {
              sVar4 = _strlen(pcStack_2ee90);
              _array_vpn_logprint(1,"aaa.c",0x83b,
                                  "do normal login failed, location not found, error %d, buf len %d\n"
                                  ,iVar2,sVar4);
            }
            uStack_2eec4 = _update_aaa_method(pcStack_2ee90,*(undefined8 *)(piStack_2ee70 + 10));
            if ((puStack_2ee78 == (undefined4 *)0x0) || (iStack_2eeb8 != 0)) {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"aaa.c",0x84a,
                                    "do normal login finished, retQRcode is true, new aaa number: %d, ctx->aaa_info->err_msd_id: %d\n"
                                    ,uStack_2eec4,
                                    *(undefined4 *)(*(long *)(piStack_2ee70 + 10) + 0x10));
              }
              if ((*(int *)(*(long *)(piStack_2ee70 + 10) + 0x10) == 0x352) ||
                 (*(int *)(*(long *)(piStack_2ee70 + 10) + 0x10) == 0x353)) {
                _vpncallback(lStack_2ee68,0xcb,*(undefined4 *)(*(long *)(piStack_2ee70 + 10) + 0x10)
                             ,*(long *)(piStack_2ee70 + 10) + 0x11062,0,0,0);
                *(char **)(piStack_2ee70 + 2) = pcStack_2ee90;
                if (pvStack_2ee88 != (void *)0x0) {
                  _free(pvStack_2ee88);
                }
                pvStack_2ee88 = (void *)0x0;
                iStack_2ee5c = iStack_2ee7c;
                goto LAB_0000dbe5;
              }
            }
            else {
              *puStack_2ee78 = uStack_2eec4;
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"aaa.c",0x846,
                                    "do normal login finished, update_aaa_method return new aaa number is %d\n"
                                    ,uStack_2eec4);
              }
            }
          }
          if (_array_vpn_log_level_ < 2) {
            _array_vpn_logprint(1,"aaa.c",0x855,
                                "do normal login, response location %s, retQRcode:%d, ctx->loopnum:%d\n"
                                ,local_58,iStack_2eeb8,CONCAT44(uVar7,piStack_2ee70[0xc]));
          }
          if (*(char *)(lStack_2ee68 + 0xe3f2) == '\x01') {
            ___memset_chk(lStack_2ee68 + 0xe3f3,0,0x200,0xffffffffffffffff);
            uStack_2eec8 = 0x1ff;
            _get_err_msg_from_resp
                      (pcStack_2ee90,"var _AN_str_errormsg =",uStack_2ee94,lStack_2ee68 + 0xe3f3,
                       &uStack_2eec8);
          }
          if (((iStack_2eeb8 == 1) && (piStack_2ee70[0xc] < 0x78)) &&
             (((pcStack_2ee90 != (char *)0x0 &&
               (pcVar3 = _strstr(pcStack_2ee90,"_AN_str_errormsg_login = \"RS"),
               pcVar3 != (char *)0x0)) || (sVar4 = _strlen(local_58), sVar4 == 0)))) {
            *piStack_2ee70 = 1;
            piStack_2ee70[0xc] = piStack_2ee70[0xc] + 1;
            *(char **)(piStack_2ee70 + 2) = pcStack_2ee90;
            if (pvStack_2ee88 != (void *)0x0) {
              _free(pvStack_2ee88);
            }
            pvStack_2ee88 = (void *)0x0;
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"aaa.c",0x864,
                                  "do normal login: callback VPN_QRCODE_SCANNING....: loopnum:%d",
                                  piStack_2ee70[0xc]);
            }
            iStack_2eea4 = 0x78 - piStack_2ee70[0xc];
            _vpncallback(lStack_2ee68,0xc9,iStack_2eea4,0,0,0,0);
            _sleep_sec(1);
            iStack_2ee5c = 0;
          }
          else {
            if ((0x77 < piStack_2ee70[0xc]) &&
               (((pcStack_2ee90 != (char *)0x0 &&
                 (pcVar3 = _strstr(pcStack_2ee90,"_AN_str_errormsg_login = \"RS"),
                 pcVar3 != (char *)0x0)) || (sVar4 = _strlen(local_58), sVar4 == 0)))) {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"aaa.c",0x86e,
                                    "do normal login: callback VPN_QRCODE_FAILED....: loopnum:%d",
                                    piStack_2ee70[0xc]);
              }
              _vpncallback(lStack_2ee68,0xcb,0,0,0,0,0);
              iStack_2ee7c = 0x84;
            }
            iVar2 = _get_url_category(local_58);
            *piStack_2ee70 = iVar2;
            if ((*piStack_2ee70 == 4) && (iStack_2eeb8 == 1)) {
              if (_array_vpn_log_level_ < 2) {
                _array_vpn_logprint(1,"aaa.c",0x876,
                                    "do normal login: callback VPN_QRCODE_SUCCESS....: loopnum:%d",
                                    piStack_2ee70[0xc]);
              }
              _vpncallback(lStack_2ee68,0xca,0,0,0,0,0);
            }
            *(char **)(piStack_2ee70 + 2) = pcStack_2ee90;
            if (pvStack_2ee88 != (void *)0x0) {
              _free(pvStack_2ee88);
            }
            pvStack_2ee88 = (void *)0x0;
            iStack_2ee5c = iStack_2ee7c;
          }
        }
        else {
          if (_array_vpn_log_level_ < 3) {
            _array_vpn_logprint(2,"aaa.c",0x80a,
                                "do normal login, failed to download page, error %d\n",iStack_2ee7c)
            ;
          }
          if (pvStack_2ee88 != (void *)0x0) {
            _free(pvStack_2ee88);
          }
          pvStack_2ee88 = (void *)0x0;
          iStack_2ee5c = iStack_2ee7c;
        }
      }
      else {
        if (_array_vpn_log_level_ < 3) {
          _array_vpn_logprint(2,"aaa.c",1999,
                              "do normal login, failed to build login request, error %d\n",
                              iStack_2ee7c);
        }
        iStack_2ee5c = iStack_2ee7c;
      }
    }
  }
LAB_0000dbe5:
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_10) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return iStack_2ee5c;
}

 (GhidraScript)  
===== do_challenge @ 000106e0 ===== (GhidraScript)  
int _do_challenge(long param_1,undefined4 *param_2,undefined4 *param_3)

{
  __uint16_t _Var1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  size_t sVar5;
  long lVar6;
  void *pvVar7;
  undefined8 in_stack_ffffffffffff2e00;
  undefined8 in_stack_ffffffffffff2e08;
  undefined4 uVar8;
  uint local_d1d8;
  undefined4 local_d1bc;
  int local_d1b8;
  uint local_d1b4;
  void *local_d1b0;
  int local_d1a8;
  int local_d1a4;
  undefined4 *local_d1a0;
  undefined4 *local_d198;
  long local_d190;
  undefined1 local_d188 [256];
  undefined1 local_d088 [4096];
  undefined1 local_c088 [1024];
  undefined1 local_bc88 [12304];
  undefined1 local_8c78 [64];
  undefined1 local_8c38 [770];
  undefined1 auStack_8936 [34574];
  undefined1 local_228 [256];
  undefined1 auStack_128 [256];
  long local_28;
  
  uVar4 = (undefined4)((ulong)in_stack_ffffffffffff2e00 >> 0x20);
  uVar8 = (undefined4)((ulong)in_stack_ffffffffffff2e08 >> 0x20);
  local_28 = *(long *)PTR____stack_chk_guard_002e4060;
  local_d1a8 = -1;
  local_d1b0 = (void *)0x0;
  local_d1b8 = 0x8a0b;
  local_d1a0 = param_3;
  local_d198 = param_2;
  local_d190 = param_1;
  _memset(local_8c78,0,0x40);
  _memset(local_bc88,0,0x3001);
  _memset(local_c088,0,0x400);
  _memset(local_d088,0,0x1000);
  if (_array_vpn_log_level_ < 2) {
    _array_vpn_logprint(1,"aaa.c",0x9b9,"do challenge\n");
  }
  local_d1a4 = _download_page(local_d190,"/prx/000/http/localhost/challenge",&local_d1b0,&local_d1b4
                             );
  if (local_d1a4 == 0) {
    if (_array_vpn_log_level_ < 2) {
      _array_vpn_logprint(1,"aaa.c",0x9be,"do challenge, resp: \n%s\n",local_d1b0);
    }
    iVar2 = _get_challenge_info(local_d1b0,local_228);
    if (iVar2 == 0) {
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x9c6,"do challenge, information: %s\n",local_228);
      }
      if (_array_vpn_log_level_ < 2) {
        _array_vpn_logprint(1,"aaa.c",0x9c7,"do challenge, error msg:   %s\n",auStack_128);
      }
      ___memset_chk(local_8c38,0,local_d1b8,0x8a0b);
      local_d1a4 = _vpncallback(local_d190,0xf,0,local_228,0x200,local_8c38,&local_d1b8);
      if ((local_d1a4 == 0) && (local_d1b8 != 0)) {
        _memset(local_d188,0,0x100);
        _array_get_spa_sess(local_d188,0x100);
        _url_escape(auStack_8936,local_bc88);
        uVar3 = ___snprintf_chk(local_c088,0x3ff,0,0x400,"pwd=%s",local_bc88);
        iVar2 = _is_ipv6_host(local_d190 + 0x9c);
        if (iVar2 == 0) {
          sVar5 = _strlen((char *)(local_d190 + 0x817f));
          if (sVar5 == 0) {
            pvVar7 = (void *)(ulong)*(uint *)(local_d190 + 0x29c);
            ___sprintf_chk(local_d088,0,0x1000,
                           "POST %s HTTP/1.1\r\nHost: %s:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\n%s"
                           ,"/prx/000/http/localhost/challenge",local_d190 + 0x9c,pvVar7,local_d188,
                           local_d190 + 0x2a0,CONCAT44(uVar4,uVar3),local_c088);
          }
          else {
            pvVar7 = (void *)(ulong)*(uint *)(local_d190 + 0x29c);
            ___sprintf_chk(local_d088,0,0x1000,
                           "POST %s HTTP/1.1\r\nHost: %s:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s;NSCOOKIE%%3Blocalhost%%3B%%2F%%3BAN_CLIENTSEC=%s%%3B%%3B; ANsession=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\n%s"
                           ,"/prx/000/http/localhost/challenge",local_d190 + 0x9c,pvVar7,local_d188,
                           local_d190 + 0x2a0,local_d190 + 0x817f,CONCAT44(uVar8,uVar3),local_c088);
          }
        }
        else {
          sVar5 = _strlen((char *)(local_d190 + 0x817f));
          if (sVar5 == 0) {
            pvVar7 = (void *)(ulong)*(uint *)(local_d190 + 0x29c);
            ___sprintf_chk(local_d088,0,0x1000,
                           "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\n%s"
                           ,"/prx/000/http/localhost/challenge",local_d190 + 0x9c,pvVar7,local_d188,
                           local_d190 + 0x2a0,CONCAT44(uVar4,uVar3),local_c088);
          }
          else {
            pvVar7 = (void *)(ulong)*(uint *)(local_d190 + 0x29c);
            ___sprintf_chk(local_d088,0,0x1000,
                           "POST %s HTTP/1.1\r\nHost: [%s]:%u\r\nCookie: ANStandalone=true;SPA-Session=%s;%s;NSCOOKIE%%3Blocalhost%%3B%%2F%%3BAN_CLIENTSEC=%s%%3B%%3B; ANsession=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\n%s"
                           ,"/prx/000/http/localhost/challenge",local_d190 + 0x9c,pvVar7,local_d188,
                           local_d190 + 0x2a0,local_d190 + 0x817f,CONCAT44(uVar8,uVar3),local_c088);
          }
        }
        if (local_d1b0 != (void *)0x0) {
          _free(local_d1b0);
        }
        local_d1b0 = (void *)0x0;
        if (_array_vpn_log_level_ < 2) {
          lVar6 = local_d190 + 0x9c;
          _Var1 = __OSSwapInt16(*(__uint16_t *)(local_d190 + 6));
          if (_Var1 == 0) {
            local_d1d8 = *(uint *)(local_d190 + 0x29c);
          }
          else {
            _Var1 = __OSSwapInt16(*(__uint16_t *)(local_d190 + 6));
            local_d1d8 = (uint)_Var1;
          }
          pvVar7 = (void *)(ulong)local_d1d8;
          _array_vpn_logprint(1,"aaa.c",0xa02,
                              "POST %s HTTP/1.1\r\nHost: %s:%u\r\nCookie: ******\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n\r\n%s"
                              ,"/prx/000/http/localhost/challenge",lVar6,pvVar7,uVar3,local_c088);
        }
        local_d1a4 = _ssl_get_page_auto_malloc(local_d190,local_d088,&local_d1b0,&local_d1b4);
        if (local_d1a4 == 0) {
          local_d1bc = 0x3f;
          iVar2 = _get_page_location(local_d1b0,local_8c78,&local_d1bc);
          if (iVar2 == 0) {
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"aaa.c",0xa20,"challenge auth url [%s]\n",local_8c78);
            }
            uVar4 = _get_url_category(local_8c78);
            *local_d198 = uVar4;
            *(void **)(local_d198 + 2) = local_d1b0;
            local_d198[4] = 1;
            local_d1b0 = (void *)0x0;
            local_d1a4 = 0;
          }
          else {
            ___memset_chk(*(long *)(local_d198 + 10) + 0x11062,0,0x800,0xffffffffffffffff);
            local_d1a8 = _get_aaa_err_msg_id(local_d1b0,*(long *)(local_d198 + 10) + 0x11062);
            local_d1a4 = _convert_aaa_error(local_d1a8);
            if (0x4000 < local_d1b4) {
              *(undefined1 *)((long)local_d1b0 + 0x4000) = 0;
            }
            if (_array_vpn_log_level_ < 2) {
              pvVar7 = local_d1b0;
              _array_vpn_logprint(1,"aaa.c",0xa10,
                                  "challenge failed, location not found, error %d, error_msg:%s, buf:\n[%s]\n"
                                  ,local_d1a4,*(long *)(local_d198 + 10) + 0x11062,local_d1b0);
            }
            iVar2 = _update_aaa_method(local_d1b0,*(undefined8 *)(local_d198 + 10));
            if (_array_vpn_log_level_ < 2) {
              _array_vpn_logprint(1,"aaa.c",0xa15,"challenge failed: aaa_new_num:%d, aaa_err:%d\n",
                                  iVar2,local_d1a8,pvVar7);
            }
            if (((iVar2 == 0) || (local_d1a8 == 0x352)) || (local_d1a8 == 0x353)) {
              *local_d1a0 = 0;
              *(undefined4 *)(*(long *)(local_d198 + 10) + 0x10) = 0x352;
              local_d1a4 = 0x352;
            }
          }
        }
        else if (_array_vpn_log_level_ < 3) {
          _array_vpn_logprint(2,"aaa.c",0xa06,
                              "login to vpn server, failed to download page, error %d\n",local_d1a4)
          ;
        }
      }
      else {
        if (_array_vpn_log_level_ < 2) {
          _array_vpn_logprint(1,"aaa.c",0x9ce,"challenge callback isn\'t prcessed by upper layer.\n"
                             );
        }
        local_d1a4 = 0x3c;
      }
    }
    else {
      if (_array_vpn_log_level_ < 4) {
        _array_vpn_logprint(3,"aaa.c",0x9c1,"failed to parse an_smx.js:\n[%s]\n",local_d1b0);
      }
      local_d1a4 = 1;
    }
  }
  if (local_d1b0 != (void *)0x0) {
    _free(local_d1b0);
  }
  local_d1b0 = (void *)0x0;
  if (*(long *)PTR____stack_chk_guard_002e4060 != local_28) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail();
  }
  return local_d1a4;
}

 (GhidraScript)  
