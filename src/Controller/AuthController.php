<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use App\Service\FirebaseService;

class AuthController extends AbstractController
{
    private $firebaseService;

    public function __construct(FirebaseService $firebaseService)
    {
        $this->firebaseService = $firebaseService;
    }

    #[Route('/register', name: 'app_register')]
    public function register(Request $request): Response
    {
        $user = $request->getSession()->get('user');
        if ($user) {
            return $this->redirectBasedOnUserType($user['type']);
        }
        
        return $this->render('auth/register.html.twig');
    }

    #[Route('/register/submit', name: 'app_register_submit', methods: ['POST'])]
    public function registerSubmit(Request $request): Response
    {
        $user = $request->getSession()->get('user');
        if ($user) {
            return $this->redirectBasedOnUserType($user['type']);
        }
        
        $nomComplete = $request->request->get('nomComplete');
        $tel = $request->request->get('tel');
        $email = $request->request->get('email');
        $pwd = $request->request->get('pwd');
        $type = 'client';

        $existingUser = $this->firebaseService->getUserByEmail($email);
        if ($existingUser) {
            $this->addFlash('error', 'Un compte avec cet email existe déjà');
            return $this->redirectToRoute('app_register');
        }

        $hashedPassword = password_hash($pwd, PASSWORD_DEFAULT);

        $userData = [
            'nomComplete' => $nomComplete,
            'tel' => $tel,
            'email' => $email,
            'pwd' => $hashedPassword,
            'type' => $type
        ];

        $this->firebaseService->createUser($userData);
        
        $this->addFlash('success', 'Inscription réussie ! Vous pouvez maintenant vous connecter.');
        return $this->redirectToRoute('app_login');
    }

    #[Route('/login', name: 'app_login')]
    public function login(Request $request): Response
    {
        $user = $request->getSession()->get('user');
        if ($user) {
            return $this->redirectBasedOnUserType($user['type']);
        }
        
        return $this->render('auth/login.html.twig');
    }

    #[Route('/login/submit', name: 'app_login_submit', methods: ['POST'])]
    public function loginSubmit(Request $request): Response
    {
        $email = $request->request->get('email');
        $pwd = $request->request->get('pwd');

        // Correction ici : suppression de l'apostrophe supplémentaire
        $user = $this->firebaseService->getUserByEmail($email);
        
        if (!$user || !password_verify($pwd, $user['pwd'])) {
            $this->addFlash('error', 'Email ou mot de passe incorrect');
            return $this->redirectToRoute('app_login');
        }

        $session = $request->getSession();
        $session->set('user', [
            'id' => $user['key'],
            'email' => $user['email'],
            'nomComplete' => $user['nomComplete'],
            'type' => $user['type']
        ]);

        return $this->redirectBasedOnUserType($user['type']);
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(Request $request): Response
    {
        $request->getSession()->remove('user');
        return $this->redirectToRoute('app_login');
    }

    private function redirectBasedOnUserType(string $type): Response
    {
        return $type === 'admin' 
            ? $this->redirectToRoute('app_dashboard')
            : $this->redirectToRoute('front_index');
    }
}