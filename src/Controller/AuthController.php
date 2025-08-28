<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use App\Service\FirebaseService;

class AuthController extends AbstractController
{
    private $firebaseService;

    private function authenticateUser(User $user): void
    {
        $firewallName = 'main';
        // UsernamePasswordToken signature in this Symfony version: (UserInterface $user, string $firewallName, array $roles = [])
        $token = new UsernamePasswordToken(
            $user,
            $firewallName,
            $user->getRoles()
        );
        
        $this->container->get('security.token_storage')->setToken($token);
        $request = $this->container->get('request_stack')->getCurrentRequest();
        if ($request) {
            $session = $request->getSession();
            $session->set('_security_'.$firewallName, serialize($token));
            $session->set('user', [
                'email' => $user->getEmail(),
                'type' => $user->getType(),
                'roles' => $user->getRoles()
            ]);
        }
    }

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
    public function loginSubmit(Request $request, UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $entityManager): Response
    {
        $email = $request->request->get('email');
        $pwd = $request->request->get('pwd');
        $firebaseToken = $request->request->get('firebase_token');

        // Vérifier d'abord dans la base de données locale
        $userRepository = $entityManager->getRepository(User::class);
        $user = $userRepository->findOneBy(['email' => $email]);

        // Si l'utilisateur existe localement
        if ($user) {
            if ($passwordHasher->isPasswordValid($user, $pwd)) {
                $this->authenticateUser($user);
                return $this->redirectBasedOnUserType($user->getType());
            }
            $this->addFlash('error', 'Mot de passe incorrect');
            return $this->redirectToRoute('app_login');
        }

        // Si pas d'utilisateur local, essayer Firebase
        try {
            // If a firebase token is present, validate it first (existing behavior).
            if ($firebaseToken) {
                $tokenData = $this->firebaseService->verifyToken($firebaseToken);
                if ($tokenData['email'] && $tokenData['email'] === $email) {
                    // Token Firebase valide, créer un utilisateur local
                    $firebaseUser = $this->firebaseService->getUserByEmail($email);
                    if ($firebaseUser) {
                        $user = new User();
                        $user->setEmail($email);
                        $user->setNomComplete($firebaseUser['nomComplete'] ?? '');
                        $user->setType($firebaseUser['type'] ?? 'client');
                        $user->setPassword($passwordHasher->hashPassword($user, $pwd));
                        
                        // Initialize roles based on type
                        $roles = ['ROLE_USER'];
                        if (($firebaseUser['type'] ?? '') === 'admin') {
                            $roles[] = 'ROLE_ADMIN';
                        }
                        $user->setRoles($roles);
                        
                        if (isset($firebaseUser['tel'])) {
                            $user->setTel($firebaseUser['tel']);
                        }
                        
                        $entityManager->persist($user);
                        $entityManager->flush();
                        
                        $this->authenticateUser($user);
                        return $this->redirectBasedOnUserType($user->getType());
                    }
                }
            }

            // If no firebase token or token didn't match, try verifying against Firebase-stored credentials
            $firebaseUser = $this->firebaseService->getUserByEmail($email);
            if ($firebaseUser) {
                // Firebase stores hashed passwords (bcrypt via password_hash). Verify with password_verify.
                if (isset($firebaseUser['pwd']) && password_verify($pwd, $firebaseUser['pwd'])) {
                    // Create local user from Firebase data and authenticate
                    $user = new User();
                    $user->setEmail($email);
                    $user->setNomComplete($firebaseUser['nomComplete'] ?? '');
                    $user->setType($firebaseUser['type'] ?? 'client');
                    $user->setPassword($passwordHasher->hashPassword($user, $pwd));

                    $roles = ['ROLE_USER'];
                    if (($firebaseUser['type'] ?? '') === 'admin') {
                        $roles[] = 'ROLE_ADMIN';
                    }
                    $user->setRoles($roles);

                    if (isset($firebaseUser['tel'])) {
                        $user->setTel($firebaseUser['tel']);
                    }

                    $entityManager->persist($user);
                    $entityManager->flush();

                    $this->authenticateUser($user);
                    return $this->redirectBasedOnUserType($user->getType());
                }

                // If password does not match Firebase hash
                $this->addFlash('error', 'Mot de passe incorrect');
                return $this->redirectToRoute('app_login');
            }
        } catch (\Exception $e) {
            $this->addFlash('error', 'Erreur d\'authentification: ' . $e->getMessage());
            return $this->redirectToRoute('app_login');
        }

        $this->addFlash('error', 'Email ou mot de passe incorrect');
        return $this->redirectToRoute('app_login');
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(Request $request): Response
    {
        $request->getSession()->remove('user');
        return $this->redirectToRoute('app_login');
    }

    private function redirectBasedOnUserType(string $type): Response
    {
        if ($type === 'admin') {
            return $this->redirectToRoute('app_dashboard');
        }
        
        // Redirection vers la page d'accueil pour les clients
        return $this->redirectToRoute('front_index');
    }

    /**
     * @return string URL to redirect to after login success
     */
    private function getTargetPath(): string
    {
        /** @var User $user */
        $user = $this->getUser();
        if (!$user || !method_exists($user, 'getType')) {
            return 'front_index';
        }

        return $user->getRoles() !== null && in_array('ROLE_ADMIN', $user->getRoles()) 
            ? 'app_dashboard' 
            : 'front_index';
    }
}