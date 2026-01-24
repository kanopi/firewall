<?php

namespace Kanopi\Firewall\Tests\Unit;


use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Traits\FileTrait;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Abstract Class used for setting things up.
 */
abstract class AbstractTestCase extends TestCase
{

    use FileTrait;

    /**
     * Set Up Method.
     */
    protected function setUp(): void
    {
        parent::setUp();
        LoggingFactory::setLogger(LoggingFactory::create([]));
    }

    /**
     * Create a request.
     */
    protected function getRequest(string $ip = '127.0.0.1', string $event_id = 'abc'): Request
    {
        $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $ip], []);
        $request->attributes->set('x-request-id', $event_id);
        return $request;
    }

    /**
     * Generate an ID for the following Request.
     *
     * @param Request $request
     *   Request to get information from.
     *
     * @return string
     *   Return the ID associated with the request.
     */
    protected function generateId(Request $request): string
    {
        return strtoupper(md5($request->getClientIp() . time()));
    }
}