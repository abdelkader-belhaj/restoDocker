<?php

namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use App\Service\CloudinaryUploader;

class MenuFirebaseController extends AbstractController
{
    #[Route('/menus', name: 'firebase_menu_index')]
    public function index(FirebaseService $firebase): Response
    {
        $menus = $firebase->getAllMenus();
        // Ensure each menu has a 'type' key to avoid Twig errors
        foreach ($menus as &$menu) {
            if (!array_key_exists('type', $menu)) {
                $menu['type'] = null;
            }
        }
        unset($menu); // break reference

        return $this->render('menuFirebase/index.html.twig', [
            'menus' => $menus
        ]);
    }

    #[Route('/menus/add', name: 'firebase_menu_add', methods: ['GET', 'POST'])]
    public function add(Request $request, FirebaseService $firebase, CloudinaryUploader $cloudinary): Response
    {
        if ($request->isMethod('POST')) {
            $titre = trim($request->request->get('titre'));
            $description = trim($request->request->get('description'));
            $type = $request->request->get('type');
            $price = $request->request->get('price');
            $imageFile = $request->files->get('image');

            $errors = [];

            if (empty($titre)) {
                $errors[] = 'Le champ "Titre" est obligatoire.';
            }
            if (empty($description)) {
                $errors[] = 'Le champ "Description" est obligatoire.';
            }
            if (empty($type)) {
                $errors[] = 'Le champ "Type" est obligatoire.';
            }
            if (empty($price) || !is_numeric($price) || floatval($price) <= 0) {
                $errors[] = 'Le champ "Prix" est obligatoire et doit être un nombre positif.';
            }
            if (!$imageFile) {
                $errors[] = 'L\'image est requise.';
            }

            if (count($errors) > 0) {
                foreach ($errors as $error) {
                    $this->addFlash('error', $error);
                }

                $types = ['Petit déjeuner', 'Déjeuner', 'Dîner', 'Collation', 'Brunch'];
                return $this->render('menuFirebase/add.html.twig', [
                    'types' => $types
                ]);
            }

            $imageUrl = $cloudinary->uploadImage($imageFile->getPathname());

            $data = [
                'titre' => $titre,
                'description' => $description,
                'image' => $imageUrl,
                'type' => $type,
                'price' => floatval($price),
            ];

            $firebase->createMenu($data);
            $this->addFlash('success', 'Menu ajouté avec succès !');
            return $this->redirectToRoute('firebase_menu_index');
        }

        $types = ['Petit déjeuner', 'Déjeuner', 'Dîner', 'Collation', 'Brunch'];
        return $this->render('menuFirebase/add.html.twig', [
            'types' => $types
        ]);
    }

    #[Route('/menus/edit/{key}', name: 'firebase_menu_edit', methods: ['GET', 'POST'])]
    public function edit(string $key, Request $request, FirebaseService $firebase, CloudinaryUploader $cloudinary): Response
    {
        $menu = $firebase->getMenu($key);
        if (!$menu) {
            $this->addFlash('error', 'Menu non trouvé.');
            return $this->redirectToRoute('firebase_menu_index');
        }

        if ($request->isMethod('POST')) {
            $imageFile = $request->files->get('image');
            $imageUrl = $menu['image']; // Garder l'ancienne image par défaut
            
            if ($imageFile) {
                $imagePath = $imageFile->getPathname();
                $imageUrl = $cloudinary->uploadImage($imagePath);
            }

            $price = $request->request->get('price');

            if (empty($price) || !is_numeric($price) || floatval($price) <= 0) {
                $this->addFlash('error', 'Le champ "Prix" est obligatoire et doit être un nombre positif.');
                $types = ['Petit déjeuner', 'Déjeuner', 'Dîner', 'Collation', 'Brunch'];
                return $this->render('menuFirebase/edit.html.twig', [
                    'menu' => $menu,
                    'key' => $key,
                    'types' => $types
                ]);
            }

            $data = [
                'titre' => $request->request->get('titre'),
                'description' => $request->request->get('description'),
                'image' => $imageUrl,
                'type' => $request->request->get('type'),
                'price' => floatval($price),
            ];
            
            $firebase->updateMenu($key, $data);
            $this->addFlash('success', 'Menu modifié avec succès !');
            return $this->redirectToRoute('firebase_menu_index');
        }

        $types = ['Petit déjeuner', 'Déjeuner', 'Dîner', 'Collation', 'Brunch'];
        return $this->render('menuFirebase/edit.html.twig', [
            'menu' => $menu,
            'key' => $key,
            'types' => $types
        ]);
    }

    #[Route('/menus/delete/{key}', name: 'firebase_menu_delete', methods: ['POST'])]
    public function delete(string $key, FirebaseService $firebase): Response
    {
        $menu = $firebase->getMenu($key);
        if (!$menu) {
            $this->addFlash('error', 'Menu non trouvé.');
            return $this->redirectToRoute('firebase_menu_index');
        }

        $firebase->deleteMenu($key);
        $this->addFlash('success', 'Menu supprimé avec succès !');
        return $this->redirectToRoute('firebase_menu_index');
    }



     #[Route('/menuComande', name: 'commande_menu_index')]
    public function menuComande(FirebaseService $firebase): Response
    {
      
        return $this->render('menuFirebase/menuComande.html.twig', [
            
        ]);
    }

    
}
