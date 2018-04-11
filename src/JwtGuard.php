<?php

namespace Ethanzway\Auth;

use BadMethodCallException;
use Illuminate\Http\Request;
use Ethanzway\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\StatefulGuard;
use Ethanzway\JWT\JWT;
use Ethanzway\JWT\Exceptions\JWTException;
use Illuminate\Contracts\Auth\UserProvider;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;

class JwtGuard implements StatefulGuard
{
    use GuardHelpers;

    protected $lastAttempted;

    protected $jwt;

    protected $request;

    public function __construct(UserProvider $provider, JWT $jwt, Request $request)
    {
        $this->provider = $provider;
        $this->jwt = $jwt;
        $this->request = $request;
    }

    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if ($this->jwt->setRequest($this->request)->getToken() && ($payload = $this->jwt->check(true))) {
            return $this->user = $this->provider->retrieveById($payload['sub']);
        }
    }

    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    public function onceUsingId($id)
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    public function validate(array $credentials = [])
    {
        return (bool) $this->attempt($credentials, false);
    }

    public function attempt(array $credentials = [], $login = true)
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    public function refresh($forceForever = false, $resetClaims = false)
    {
        return $this->requireToken()->refresh($forceForever, $resetClaims);
    }

    public function loginUsingId($id, $remember = false)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    public function login(AuthenticatableContract $user, $remember = false)
    {
        $this->setUser($user);

        return $this->jwt->fromSubject($user, $user->getAuthIdentifier(), []);
    }

    public function logout($forceForever = false)
    {
        $this->requireToken()->invalidate($forceForever);

        $this->user = null;
        $this->jwt->unsetToken();
    }

    public function viaRemember()
    {
        return false;
    }

    public function getProvider()
    {
        return $this->provider;
    }

    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;

        return $this;
    }

    public function getUser()
    {
        return $this->user;
    }

    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }

    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }

    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    protected function hasValidCredentials($user, $credentials)
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    protected function requireToken()
    {
        if (! $this->jwt->setRequest($this->getRequest())->getToken()) {
            throw new JWTException('Token could not be parsed from the request.');
        }

        return $this->jwt;
    }
}
