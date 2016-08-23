{******************************************************************************

  Fix of TIdCookie.ParseServerCookie:
  http://blog.coolsoftware.ru/2016/08/delphi-xe2-indy-parse-cookie-bug.html

  Tested on Delphi XE 2

  Copyright (c) 2016 by Vitaly Yakovlev.
  http://blog.coolsoftware.ru/

  This package is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License

  It is distributed in the hope that it will be useful,
  but without any warranty.

  Please, don't remove this copyright.

*******************************************************************************}

unit VCookieManager;

interface

uses
  Classes, IdCookieManager;

type
  TVCookieManager = class(TIdCookieManager)
  protected
    procedure DoOnCreate; override;
  end;

implementation

uses
  SysUtils, IdCookie, IdGlobal, IdGlobalProtocols, IdURI;

type
  TVCookies = class(TIdCookies)
  public
    constructor Create(AOwner: TPersistent);
  end;

  TVCookie = class(TIdCookie)
  public
    function ParseServerCookie(const ACookieText: String; AURI: TIdURI): Boolean; override;
  end;

{ TVCookieManager }

procedure TVCookieManager.DoOnCreate;
begin
  FreeAndNil(FCookieCollection);
  FCookieCollection := TVCookies.Create(Self);
  inherited;
end;

{ TVCookies }

constructor TVCookies.Create(AOwner: TPersistent);
begin
  TOwnedCollection(Self).Create(AOwner, TVCookie);
  // TIdCookies
  FRWLock := TMultiReadExclusiveWriteSynchronizer.Create;
  FCookieList := TIdCookieList.Create;
end;

{ TVCookie }

function GetDefaultPath(const AURL: TIdURI): String;
begin
  if not TextStartsWith(AURL.Path, '/') then begin {do not localize}
    Result := '/'; {do not localize}
  end
  else if AURL.Path = '/' then begin {do not localize}
    Result := '/'; {do not localize}
  end else begin
    Result := Copy(AURL.Path, 1, RPos('/', AURL.Path)-1);
  end;
end;

function IsHTTP(const AProtocol: String): Boolean;
begin
  Result := PosInStrArray(AProtocol, ['http', 'https'], False) <> -1; {do not localize}
end;

function TVCookie.ParseServerCookie(const ACookieText: String;
  AURI: TIdURI): Boolean;
const
  cTokenSeparators = '()<>@,;:\"/[]?={} '#9;
var
  CookieProp: TStringList;
  S: string;
  LSecs: Int64;

  procedure SplitCookieText;
  var
    LNameValue, LAttrs, LAttr, LName, LValue: String;
    LExpiryTime: TDateTime;
    i: Integer;
  begin
    I := Pos(';', ACookieText);
    if I > 0 then
    begin
      LNameValue := Copy(ACookieText, 1, I-1);
      LAttrs := Copy(ACookieText, I, MaxInt);
    end else
    begin
      LNameValue := ACookieText;
      LAttrs := '';
    end;

    I := Pos('=', LNameValue);
    if I = 0 then begin
      Exit;
    end;

    LName := Trim(Copy(LNameValue, 1, I-1));
    if LName = '' then begin
      Exit;
    end;

    LValue := Trim(Copy(LNameValue, I+1, MaxInt));
    if TextStartsWith(LValue, '"') then begin
      IdDelete(LValue, 1, 1);
      LNameValue := LValue;
      LValue := Fetch(LNameValue, '"');
    end;
    CookieProp.Add(LName + '=' + LValue);

    while LAttrs <> '' do
    begin
      IdDelete(LAttrs, 1, 1);
      I := Pos(';', LAttrs);
      if I > 0 then begin
        LAttr := Copy(LAttrs, 1, I-1);
        LAttrs := Copy(LAttrs, I, MaxInt);
      end else begin
        LAttr := LAttrs;
        LAttrs := '';
      end;
      I := Pos('=', LAttr);
      if I > 0 then begin
        LName := Trim(Copy(LAttr, 1, I-1));
        LValue := Trim(Copy(LAttr, I+1, MaxInt));
        // RLebeau: draft-23 does not (yet?) account for quoted attribute
        // values, despite several complaints asking for it.  We'll do it
        // anyway in the hopes that the draft will "do the right thing" by
        // the time it is finalized...
        if TextStartsWith(LValue, '"') then begin
          IdDelete(LValue, 1, 1);
          LNameValue := LValue;
          LValue := Fetch(LNameValue, '"');
        end;
      end else begin
        LName := Trim(LAttr);
        LValue := '';
      end;

      case PosInStrArray(LName, ['Expires', 'Max-Age', 'Domain', 'Path', 'Secure', 'HttpOnly'], False) of
        0: begin
          if TryStrToInt64(LValue, LSecs) then begin
            // Not in the RFCs, but some servers specify Expires as an
            // integer number in seconds instead of using Max-Age...
            if LSecs >= 0 then begin
              LExpiryTime := (Now + LSecs * 1000 / MSecsPerDay);
            end else begin
              LExpiryTime := EncodeDate(1, 1, 1);
            end;
            CookieProp.Add('EXPIRES=' + FloatToStr(LExpiryTime));
          end else
          begin
            LExpiryTime := CookieStrToLocalDateTime(LValue);
            if LExpiryTime <> 0.0 then begin
              CookieProp.Add('EXPIRES=' + FloatToStr(LExpiryTime));
            end;
          end;
        end;
        1: begin
          if TryStrToInt64(LValue, LSecs) then begin
            if LSecs >= 0 then begin
              LExpiryTime := (Now + LSecs * 1000 / MSecsPerDay);
            end else begin
              LExpiryTime := EncodeDate(1, 1, 1);
            end;
            CookieProp.Add('MAX-AGE=' + FloatToStr(LExpiryTime));
          end;
        end;
        2: begin
          if LValue <> '' then begin
            if TextStartsWith(LValue, '.') then begin {do not localize}
              LValue := Copy(LValue, 2, MaxInt);
            end;
            // RLebeau: have encountered one cookie in the 'Set-Cookie' header that
            // includes a port number in the domain, though the RFCs do not indicate
            // this is allowed. RFC 2965 defines an explicit "port" attribute in the
            // 'Set-Cookie2' header for that purpose instead. We'll just strip it off
            // here if present...
            I := Pos(':', LValue);
            if I > 0 then begin
              LValue := Copy(S, 1, I-1);
            end;
            CookieProp.Add('DOMAIN=' + LowerCase(LValue));
          end;
        end;
        3: begin
          if (LValue = '') or (not TextStartsWith(LValue, '/')) then begin
            LValue := GetDefaultPath(AURI);
          end;
          CookieProp.Add('PATH=' + LValue);
        end;
        4: begin
          CookieProp.Add('SECURE=');
        end;
        5: begin
          CookieProp.Add('HTTPONLY=');
        end;
      end;
    end;
  end;

  // Vitaly Yakovlev 23.08.2016 fix: var VValue -> out VValue
  function GetLastValueOf(const AName: String; out VValue: String): Boolean;
  var
    I: Integer;
  begin
    Result := False;
    for I := CookieProp.Count-1 downto 0 do
    begin
      if TextIsSame(CookieProp.Names[I], AName) then
      begin
        {$IFDEF HAS_TStrings_ValueFromIndex}
        VValue := CookieProp.ValueFromIndex[I];
        {$ELSE}
        VValue := Copy(CookieProp[I], Pos('=', CookieProp[I])+1, MaxInt); {Do not Localize}
        {$ENDIF}
        Result := True;
        Exit;
      end;
    end;
  end;

begin
  Result := False;

  // using the algorithm defined in draft-23 section 5.1.3...

  CookieProp := TStringList.Create;
  try
    SplitCookieText;
    if CookieProp.Count = 0 then begin
      Exit;
    end;

    CookieName := CookieProp.Names[0];
    {$IFDEF HAS_TStrings_ValueFromIndex}
    Value := CookieProp.ValueFromIndex[0];
    {$ELSE}
    S := CookieProp[0];
    Value := Copy(S, Pos('=', S)+1, MaxInt);
    {$ENDIF}
    CookieProp.Delete(0);

    CreatedAt := Now;
    LastAccessed := CreatedAt;

    // using the algorithms defined in draft-23 section 5.3...

    if GetLastValueOf('MAX-AGE', S) then begin {Do not Localize}
      Persistent := True;
      Expires := StrToFloat(S);
    end
    else if GetLastValueOf('EXPIRES', S) then {Do not Localize}
    begin
      Persistent := True;
      Expires := StrToFloat(S);
    end else
    begin
      Persistent := False;
      Expires := EncodeDate(9999, 12, 31) + EncodeTime(23, 59, 59, 999);
    end;

    if GetLastValueOf('DOMAIN', S) then {Do not Localize}
    begin

      {
        If the user agent is configured to reject "public suffixes" and
        the domain-attribute is a public suffix:

           If the domain-attribute is identical to the canonicalized
           request-host:

              Let the domain-attribute be the empty string.

           Otherwise:

              Ignore the cookie entirely and abort these steps.

           NOTE: A "public suffix" is a domain that is controlled by a
           public registry, such as "com", "co.uk", and "pvt.k12.wy.us".
           This step is essential for preventing attacker.com from
           disrupting the integrity of example.com by setting a cookie
           with a Domain attribute of "com".  Unfortunately, the set of
           public suffixes (also known as "registry controlled domains")
           changes over time.  If feasible, user agents SHOULD use an
           up-to-date public suffix list, such as the one maintained by
           the Mozilla project at <http://publicsuffix.org/>.
      }
    end;

    if Length(S) > 0 then
    begin
      if not IsDomainMatch(AURI.Host, S) then begin
        Exit;
      end;
      HostOnly := False;
      Domain := S;
    end else
    begin
      HostOnly := True;
      Domain := CanonicalizeHostName(AURI.Host);
    end;

    if GetLastValueOf('PATH', S) then begin {Do not Localize}
      Path := S;
    end else begin
      Path := GetDefaultPath(AURI);
    end;

    Secure := CookieProp.IndexOfName('SECURE') <> -1; { Do not Localize }
    HttpOnly := CookieProp.IndexOfName('HTTPONLY') <> -1; { Do not Localize }

    if HttpOnly and (not IsHTTP(AURI.Protocol)) then begin
      Exit;
    end;

    Result := True;
  finally
    FreeAndNil(CookieProp);
  end;
end;

end.
