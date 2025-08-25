<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HealthController
{
    #[Route('/health', name: 'health_check')]
    public function check(): Response
    {
        return new Response('OK', 200);
    }
}
