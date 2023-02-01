<?php

namespace Illuminate\Auth\Passwords;

use Carbon\Carbon;
use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Auth\CanResetPassword as CanResetPasswordContract;
use Illuminate\Contracts\Auth\PasswordBroker as PasswordBrokerContract;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use UnexpectedValueException;

class PasswordBroker implements PasswordBrokerContract
{
    /**
     * The number of seconds the reset link should be active for.
     *
     * @var int
     */
    protected $expires = 3600;

    /**
     * Minimum number of seconds before re-sending a new reset link.
     *
     * @var int
     */
    protected $throttle = 60;

    /**
     * The callback that should be used to create the reset password URL.
     *
     * @var (\Closure(mixed, string): string)|null
     */
    protected $createUrlCallback;

    /**
     * The callback that should be used to validate the reset request.
     *
     * @var (\Closure(mixed, string): string)|null
     */
    protected $validateRequestCallback;

    /**
     * The user provider implementation.
     *
     * @var \Illuminate\Contracts\Auth\UserProvider
     */
    protected UserProvider $users;

    /**
     * The rate limiter.
     *
     * @var \Illuminate\Cache\RateLimiter
     */
    protected RateLimiter $limiter;

    /**
     * The URL generator instance.
     *
     * @var \Illuminate\Routing\UrlGenerator
     */
    protected UrlGenerator $generator;

    /**
     * Create a new password broker instance.
     *
     * @param UserProvider $users
     * @param RateLimiter $limiter
     * @param UrlGenerator $generator
     */
    public function __construct(UserProvider $users, RateLimiter $limiter, UrlGenerator $generator)
    {
        $this->users = $users;
        $this->limiter = $limiter;
        $this->generator = $generator;
    }

    /**
     * Send a password reset link to a user.
     *
     * @param  array  $credentials
     * @param  \Closure|null  $callback
     * @return string
     */
    public function sendResetLink(array $credentials, Closure $callback = null)
    {
        // First we will check to see if we found a user at the given credentials and
        // if we did not we will redirect back to this current URI with a piece of
        // "flash" data in the session to indicate to the developers the errors.
        $user = $this->getUser($credentials);

        if (is_null($user)) {
            return static::INVALID_USER;
        }

        if ($this->limiter->tooManyAttempts($this->throttleKey($user), 1)) {
            return static::RESET_THROTTLED;
        }

        $this->limiter->hit($this->throttleKey($user), $this->throttle);

        $url = $this->resetUrl($user);

        if ($callback) {
            $callback($user, $url);
        } else {
            // Once we have the reset URL, we are ready to send it to the
            // user to reset their password. We can then redirect back
            // to the current URI with no errors set in the session.
            $user->sendPasswordResetNotification($url);
        }

        return static::RESET_LINK_SENT;
    }

    /**
     * Reset the password for the given request.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  array  $credentials
     * @param  \Closure  $callback
     * @return mixed
     */
    public function reset(Request $request, array $credentials, Closure $callback)
    {
        $user = $this->validateReset($request, $credentials);

        // If the responses from the validate method is not a user instance, we will
        // assume that it is a redirect and simply return it from this method and
        // the user is properly redirected having an error message on the post.
        if (! $user instanceof CanResetPasswordContract) {
            return $user;
        }

        $password = $credentials['password'];

        // Once the reset has been validated, we'll call the given callback with the
        // new password. This gives the user an opportunity to store the password
        // in their persistent storage. Then we'll delete the token and return.
        $callback($user, $password);

        return static::PASSWORD_RESET;
    }

    /**
     * Validate a password reset for the given credentials.
     *
     * @param  \Illuminate\Http\Request $request
     * @param  array  $credentials
     * @return CanResetPasswordContract|string
     */
    protected function validateReset(Request $request, array $credentials)
    {
        if (is_null($user = $this->getUser($credentials))) {
            return static::INVALID_USER;
        }

        if ($this->validateRequestCallback) {
            return call_user_func($this->validateRequestCallback, $request, $credentials) ?: $user;
        }

        if (! $this->generator->hasValidSignature($request)) {
            return static::INVALID_SIGNATURE;
        }

        return $user;
    }

    /**
     * Get the user for the given credentials.
     *
     * @param  array  $credentials
     * @return CanResetPasswordContract|null
     *
     * @throws \UnexpectedValueException
     */
    public function getUser(array $credentials)
    {
        $credentials = Arr::except($credentials, ['token']);

        $user = $this->users->retrieveByCredentials($credentials);

        if ($user && ! $user instanceof CanResetPasswordContract) {
            throw new UnexpectedValueException('User must implement CanResetPassword interface.');
        }

        return $user;
    }

    /**
     * Get the reset URL for the given user.
     *
     * @param  \Illuminate\Contracts\Auth\CanResetPassword $user
     * @return string
     */
    protected function resetUrl(CanResetPasswordContract $user): string
    {
        if ($this->createUrlCallback) {
            return call_user_func($this->createUrlCallback, $user);
        }

        return $this->generator->temporarySignedRoute(
            'password.reset',
            Carbon::now()->addSeconds($this->expires),
            ['email' => $user->getEmailForPasswordReset()]
        );
    }

    /**
     * Set a callback that should be used when creating the reset password button URL.
     *
     * @param  \Closure(mixed, string): string  $callback
     * @return void
     */
    public function createUrlUsing($callback)
    {
        $this->createUrlCallback = $callback;
    }

    /**
     * Set a callback that should be used when validating the reset request.
     *
     * @param  \Closure(mixed, string): string  $callback
     * @return void
     */
    public function validateRequestUsing($callback)
    {
        $this->validateRequestCallback = $callback;
    }

    /**
     * The number of minutes the reset link should be active for.
     */
    public function setResetLinkExpiry(int $expires)
    {
        $this->expires = $expires * 60;
    }

    /**
     * Minimum number of seconds before re-sending a new reset link.
     */
    public function setResetLinkThrottle(int $throttle)
    {
        $this->throttle = $throttle;
    }

    /**
     * Get the rate limiting throttle key for the request.
     */
    protected function throttleKey(CanResetPasswordContract $user): string
    {
        return "reset-password:{$user->getEmailForPasswordReset()}";
    }
}
