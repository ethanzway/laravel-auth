<?php

namespace Ethanzway\Auth;

use Ethanzway\Auth\Access\Gate;
use Ethanzway\Auth\Console\AuthMakeCommand;
use Ethanzway\Auth\Console\AuthTableCommand;
use Ethanzway\Auth\Console\ClearResetsCommand;
use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * Boot the service provider.
     *
     * @return void
     */
    public function boot()
	{
        $path = realpath(__DIR__.'/../config/config.php');

        $this->publishes([$path => config_path('auth.php')], 'config');
        $this->mergeConfigFrom($path, 'auth');
		
		$this->commands([
			'AuthMake' => 'command.auth.make',
			'ClearResets' => 'command.auth.resets.clear',
		]);
	}

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerAuthenticator();

        $this->registerUserResolver();

        $this->registerAccessGate();

        $this->registerRequestRebindHandler();

        $this->registerAuthMakeCommand();

        $this->registerClearResetsCommand();
    }

    /**
     * Register the authenticator services.
     *
     * @return void
     */
    protected function registerAuthenticator()
    {
        $this->app->singleton('auth', function ($app) {
            // Once the authentication service has actually been requested by the developer
            // we will set a variable in the application indicating such. This helps us
            // know that we need to set any queued cookies in the after event later.
            $app['auth.loaded'] = true;

            return new AuthManager($app);
        });

        $this->app->singleton('auth.driver', function ($app) {
            return $app['auth']->guard();
        });
    }

    /**
     * Register a resolver for the authenticated user.
     *
     * @return void
     */
    protected function registerUserResolver()
    {
        $this->app->bind(
            AuthenticatableContract::class, function ($app) {
                return call_user_func($app['auth']->userResolver());
            }
        );
    }

    /**
     * Register the access gate service.
     *
     * @return void
     */
    protected function registerAccessGate()
    {
        $this->app->singleton(GateContract::class, function ($app) {
            return new Gate($app, function () use ($app) {
                return call_user_func($app['auth']->userResolver());
            });
        });
    }

    /**
     * Register a resolver for the authenticated user.
     *
     * @return void
     */
    protected function registerRequestRebindHandler()
    {
        $this->app->rebinding('request', function ($app, $request) {
            $request->setUserResolver(function ($guard = null) use ($app) {
                return call_user_func($app['auth']->userResolver(), $guard);
            });
        });
    }
	
    /**
     * Register the command.
     *
     * @return void
     */
    protected function registerAuthMakeCommand()
    {
        $this->app->singleton('command.auth.make', function ($app) {
            return new AuthMakeCommand;
        });
    }

    /**
     * Register the command.
     *
     * @return void
     */
    protected function registerClearResetsCommand()
    {
        $this->app->singleton('command.auth.resets.clear', function () {
            return new ClearResetsCommand;
        });
    }
}
