<?php

namespace App\Security;

use Kreait\Firebase\Contract\Auth as FirebaseAuth;
use Kreait\Firebase\Factory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class FirebaseAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
	private FirebaseAuth $auth;

	public function __construct()
	{
		$factory = (new Factory())
			->withServiceAccount(__DIR__ . '/../../config/firebase/symfony07-firebase-adminsdk-fbsvc-f3febd9084.json')
			->withDatabaseUri('https://symfony07-default-rtdb.firebaseio.com');
		$this->auth = $factory->createAuth();
	}

	public function supports(Request $request): ?bool
	{
		$authHeader = $request->headers->get('Authorization');
		return !empty($authHeader) && str_starts_with($authHeader, 'Bearer ');
	}

	public function authenticate(Request $request): Passport
	{
		$authHeader = $request->headers->get('Authorization');
		if (empty($authHeader)) {
			throw new CustomUserMessageAuthenticationException('Token Firebase manquant');
		}

		$token = str_replace('Bearer ', '', $authHeader);
		if (empty($token)) {
			throw new CustomUserMessageAuthenticationException('Token Firebase invalide');
		}

		try {
			$verifiedToken = $this->auth->verifyIdToken($token);
			// Extraction manuelle de l'UID depuis le token JWT
			$tokenParts = explode('.', $token);
			$payload = json_decode(base64_decode($tokenParts[1]), true);
			$uid = $payload['user_id'] ?? $payload['sub'] ?? null;
			if (empty($uid)) {
				throw new CustomUserMessageAuthenticationException('Token invalide : ID utilisateur manquant');
			}
			try {
				$firebaseUser = $this->auth->getUser($uid);
				return new SelfValidatingPassport(
					new UserBadge($uid, function() use ($firebaseUser): UserInterface {
						return new InMemoryUser(
							$firebaseUser->email,
							null,
							['ROLE_USER']
						);
					})
				);
			} catch (\Exception $e) {
				throw new CustomUserMessageAuthenticationException('Utilisateur Firebase non trouvé');
			}
		} catch (\Exception $e) {
			throw new CustomUserMessageAuthenticationException('Token Firebase invalide: ' . $e->getMessage());
		}
	}

	public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
	{
		$user = $token->getUser();

		if ($user instanceof UserInterface) {
			// Redirection basée sur le type (client ou admin)
			$roles = $user->getRoles();
			if (in_array('admin', $roles)) {
				return new JsonResponse(['message' => 'Connexion réussie', 'redirect' => '/dashboard']);
			} elseif (in_array('client', $roles)) {
				return new JsonResponse(['message' => 'Connexion réussie', 'redirect' => '/front']);
			}
		}

		return new JsonResponse(['message' => 'Connexion réussie'], Response::HTTP_OK);
	}

	public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
	{
		return new JsonResponse([
			'message' => 'Échec de l\'authentification',
			'erreur' => $exception->getMessage()
		], Response::HTTP_UNAUTHORIZED);
	}

	public function start(Request $request, AuthenticationException $authException = null): Response
	{
		return new JsonResponse([
			'message' => 'Authentification requise',
			'erreur' => $authException ? $authException->getMessage() : 'Aucun token d\'authentification fourni'
		], Response::HTTP_UNAUTHORIZED);
	}
}
