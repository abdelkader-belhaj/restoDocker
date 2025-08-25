<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class HealthControllerPhpController extends AbstractController
{
    #[Route('/health', name: 'health_check')]
public function check(): Response
{
    return new Response('OKh', 200);
}
}
