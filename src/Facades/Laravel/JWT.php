<?php 
namespace Xaamin\JWT\Facades\Laravel;

use Illuminate\Support\Facades\Facade;

class JWT extends Facade 
{
    protected static function getFacadeAccessor()
    {
        return 'Xaamin\JWT\JWT';
    }
}