<?php
namespace App\Controller;

use App\Service\CloudinaryUploader;
use App\Service\FirebaseService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class ChefController extends AbstractController
{
    private FirebaseService $firebaseService;

    public function __construct(FirebaseService $firebaseService)
    {
        $this->firebaseService = $firebaseService;
    }

    #[Route('/admin/chefs', name: 'chefs_list')]
    public function index(): Response
    {
        $chefs = $this->firebaseService->getAllChefs();
        return $this->render('chefs/index.html.twig', ['chefs' => $chefs]);
    }

    #[Route('/admin/chefs/create', name: 'chefs_create')]
    public function create(Request $request, CloudinaryUploader $cloudinary): Response
    {
        if ($request->isMethod('POST')) {
            $imageFile = $request->files->get('image');
            $imageUrl = null;
            if ($imageFile) {
                $imageUrl = $cloudinary->uploadImage($imageFile->getPathname());
            }

            $data = [
                'nom' => $request->request->get('nom'),
                'titre' => $request->request->get('titre'),
                'image' => $imageUrl,
            ];

            $this->firebaseService->createChef($data);
            return $this->redirectToRoute('chefs_list');
        }

        return $this->render('chefs/create.html.twig');
    }

    #[Route('/admin/chefs/edit/{key}', name: 'chefs_edit')]
    public function edit(string $key, Request $request, CloudinaryUploader $cloudinary): Response
    {
        $chef = $this->firebaseService->getChef($key);
        if (!$chef) {
            throw $this->createNotFoundException("Chef non trouvé !");
        }

        if ($request->isMethod('POST')) {
            $imageFile = $request->files->get('image');
            $imageUrl = $chef['image'] ?? null;

            if ($imageFile) {
                $imageUrl = $cloudinary->uploadImage($imageFile->getPathname());
            }

            $data = [
                'nom' => $request->request->get('nom'),
                'titre' => $request->request->get('titre'),
                'image' => $imageUrl,
            ];

            $this->firebaseService->updateChef($key, $data);
            return $this->redirectToRoute('chefs_list');
        }

        return $this->render('chefs/edit.html.twig', ['chef' => $chef, 'key' => $key]);
    }

    #[Route('/admin/chefs/delete/{key}', name: 'chefs_delete', methods: ['POST'])]
    public function delete(string $key): Response
    {
        $this->firebaseService->deleteChef($key);
        return $this->redirectToRoute('chefs_list');
    }
}
