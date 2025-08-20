<?php


namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use App\Service\CloudinaryUploader;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ParttiesController extends AbstractController
{
    #[Route('/partties', name: 'app_partties_index')]
    public function index(FirebaseService $firebase): Response
    {
        $partties = $firebase->getAllPartties();

        return $this->render('partties/index.html.twig', [
            'partties' => $partties,
        ]);
    }

    #[Route('/partties/create', name: 'app_partties_create', methods: ['POST'])]
public function create(Request $request, FirebaseService $firebase, CloudinaryUploader $cloudinary): Response
{
    $imageFile = $request->files->get('image');
    $imageUrl = '';

    if ($imageFile) {
        $imageUrl = $cloudinary->uploadImage($imageFile->getPathname());
    }

    $data = [
        'titre' => $request->request->get('titre'),
        'price' => (int) $request->request->get('price'),
        'debut' => $request->request->get('debut'),
        'ligne1' => $request->request->get('ligne1'),
        'ligne2' => $request->request->get('ligne2'),
        'ligne3' => $request->request->get('ligne3'),
        'final' => $request->request->get('final'),
        'image' => $imageUrl,
    ];

    $firebase->createParttie($data);

    return $this->redirectToRoute('app_partties_index');
}


    #[Route('/partties/edit/{key}', name: 'app_partties_edit')]
    public function edit(string $key, FirebaseService $firebase): Response
    {
        $parttie = $firebase->getParttie($key);

        return $this->render('partties/edit.html.twig', [
            'key' => $key,
            'parttie' => $parttie,
        ]);
    }

    #[Route('/partties/update/{key}', name: 'app_partties_update', methods: ['POST'])]
    public function update(string $key, Request $request, FirebaseService $firebase): Response
    {
        $data = [
            'titre' => $request->request->get('titre'),
            'price' => (int) $request->request->get('price'),
            'debut' => $request->request->get('debut'),
            'ligne1' => $request->request->get('ligne1'),
            'ligne2' => $request->request->get('ligne2'),
            'ligne3' => $request->request->get('ligne3'),
            'final' => $request->request->get('final'),
            'image' => $request->request->get('image'),
        ];

        $firebase->updateParttie($key, $data);

        return $this->redirectToRoute('app_partties_index');
    }

    #[Route('/partties/delete/{key}', name: 'app_partties_delete')]
    public function delete(string $key, FirebaseService $firebase): Response
    {
        $firebase->deleteParttie($key);

        return $this->redirectToRoute('app_partties_index');
    }
}
