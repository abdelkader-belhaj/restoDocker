<?php

namespace App\Controller;

use App\Service\FirebaseService;
use App\Service\CloudinaryUploader;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class SpecialController extends AbstractController
{
    private FirebaseService $firebaseService;

    public function __construct(FirebaseService $firebaseService)
    {
        $this->firebaseService = $firebaseService;
    }

    #[Route('/specialee', name: 'special_index')]
    public function index(): Response
    {
        $specials = $this->firebaseService->getAllSpecials();
        return $this->render('special/index.html.twig', [
            'specials' => $specials,
        ]);
    }

    #[Route('/special/new', name: 'special_new')]
    public function new(Request $request, CloudinaryUploader $cloudinary): Response
    {
        if ($request->isMethod('POST')) {
            $imageFile = $request->files->get('image');
            $imageUrl = null;
            if ($imageFile) {
                $imagePath = $imageFile->getPathname();
                $imageUrl = $cloudinary->uploadImage($imagePath);
            }
            $data = [
                'title' => $request->request->get('title'),
                'sousTitre' => $request->request->get('sousTitre'),
                'description' => $request->request->get('description'),
                'image' => $imageUrl,
            ];
            $this->firebaseService->createSpecial($data);
            return $this->redirectToRoute('special_index');
        }
        return $this->render('special/new.html.twig');
    }

    #[Route('/special/{key}', name: 'special_show')]
    public function show(string $key): Response
    {
        $special = $this->firebaseService->getSpecial($key);
        if (!$special) {
            throw $this->createNotFoundException('Special not found');
        }
        return $this->render('special/show.html.twig', [
            'special' => $special,
            'key' => $key,
        ]);
    }

    #[Route('/special/{key}/edit', name: 'special_edit')]
    public function edit(Request $request, string $key, CloudinaryUploader $cloudinary): Response
    {
        $special = $this->firebaseService->getSpecial($key);
        if (!$special) {
            throw $this->createNotFoundException('Special not found');
        }
        if ($request->isMethod('POST')) {
            $imageFile = $request->files->get('image');
            $imageUrl = $special['image'] ?? null;
            if ($imageFile) {
                $imagePath = $imageFile->getPathname();
                $imageUrl = $cloudinary->uploadImage($imagePath);
            }
            $data = [
                'title' => $request->request->get('title'),
                'sousTitre' => $request->request->get('sousTitre'),
                'description' => $request->request->get('description'),
                'image' => $imageUrl,
            ];
            $this->firebaseService->updateSpecial($key, $data);
            return $this->redirectToRoute('special_index');
        }
        return $this->render('special/edit.html.twig', [
            'special' => $special,
            'key' => $key,
        ]);
    }

    #[Route('/special/{key}/delete', name: 'special_delete', methods: ['POST'])]
    public function delete(string $key): Response
    {
        $this->firebaseService->deleteSpecial($key);
        return $this->redirectToRoute('special_index');
    }



    #[Route('/specialss', name: 'speciale_index')]
public function indexww(): Response
{
    $specials = $this->firebaseService->getAllSpecials();
    return $this->render('special/showw.html.twig', [
        'specials' => $specials,
    ]);
}

}
