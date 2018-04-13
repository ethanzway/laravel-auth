<?php

namespace Ethanzway\Auth;

use Illuminate\Support\Str;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;

class EloquentUserProvider implements UserProvider
{
    protected $model;

    public function __construct($model)
    {
        $this->model = $model;
    }

    public function retrieveById($identifier)
    {
        $model = $this->createModel();

        return $model->newQuery()
            ->where($model->getAuthIdentifierName(), $identifier)
            ->first();
    }
	
    public function retrieveByToken($identifier, $token)
    {
    }
	
    public function updateRememberToken(UserContract $user, $token)
    {
    }
	
    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials)) {
            return;
        }

        $query = $this->createModel()->newQuery();

        foreach ($credentials as $key => $value) {
			$query->whereHas('credentials', function ($query) use ($key, $value) {
				$query->where($key, $value);
			});
        }
        return $query->first();
    }
	
    public function validateCredentials(UserContract $user, array $credentials)
    {
		return true;
    }
	
    public function createModel()
    {
        $class = '\\'.ltrim($this->model, '\\');

        return new $class;
    }
	
    public function getModel()
    {
        return $this->model;
    }
	
    public function setModel($model)
    {
        $this->model = $model;

        return $this;
    }
}
