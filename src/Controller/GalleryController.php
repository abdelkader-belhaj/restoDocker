<?php
// src/Controller/GalleryController.php

namespace App\Controller;

use App\Service\FirebaseService;
use App\Service\CloudinaryUploader;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class GalleryController extends AbstractController
{
    private FirebaseService $firebase;

    public function __construct(FirebaseService $firebase)
    {
        $this->firebase = $firebase;
    }

    #[Route('/gallery', name: 'gallery_index')]
    public function index(): Response
    {
        $galleries = $this->firebase->getAllGalleries();
        return $this->render('gallery/index.html.twig', ['galleries' => $galleries]);
    }

    #[Route('/gallery/new', name: 'gallery_new')]
    public function new(Request $request, CloudinaryUploader $cloudinary): Response
    {
        if ($request->isMethod('POST')) {
            $imageFile = $request->files->get('image');
            $imageUrl = null;

            if ($imageFile) {
                $imageUrl = $cloudinary->uploadImage($imageFile->getPathname());
            }

            $this->firebase->createGallery([
                'image' => $imageUrl,
            ]);

            return $this->redirectToRoute('gallery_index');
        }

        return $this->render('gallery/new.html.twig');
    }

    #[Route('/gallery/{key}', name: 'gallery_show')]
    public function show(string $key): Response
    {
        $gallery = $this->firebase->getGallery($key);
        if (!$gallery) {
            throw $this->createNotFoundException('Image non trouvée');
        }

        return $this->render('gallery/show.html.twig', [
            'gallery' => $gallery,
            'key' => $key,
        ]);
    }

    #[Route('/gallery/{key}/edit', name: 'gallery_edit')]
    public function edit(Request $request, string $key, CloudinaryUploader $cloudinary): Response
    {
        $gallery = $this->firebase->getGallery($key);
        if (!$gallery) {
            throw $this->createNotFoundException('Image non trouvée');
        }

        if ($request->isMethod('POST')) {
            $imageFile = $request->files->get('image');
            $imageUrl = $gallery['image'] ?? null;

            if ($imageFile) {
                $imageUrl = $cloudinary->uploadImage($imageFile->getPathname());
            }

            $this->firebase->updateGallery($key, ['image' => $imageUrl]);

            return $this->redirectToRoute('gallery_index');
        }

        return $this->render('gallery/edit.html.twig', [
            'gallery' => $gallery,
            'key' => $key,
        ]);
    }

    #[Route('/gallery/{key}/delete', name: 'gallery_delete', methods: ['POST'])]
    public function delete(string $key): Response
    {
        $this->firebase->deleteGallery($key);
        return $this->redirectToRoute('gallery_index');
    }
}
