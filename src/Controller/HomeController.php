<?php

// src/Controller/HomeController.php
namespace App\Controller;

use App\Service\FirebaseService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class HomeController extends AbstractController
{
    #[Route('/home/menu', name: 'app_menus_home')]
    public function show(Request $request, FirebaseService $firebase): Response
    {
        $user = $request->getSession()->get('user');
        
        if (!$user || $user['type'] !== 'client') {
            return $this->redirectToRoute('app_login');
        }
        
        $menus = $firebase->getAllMenus();
        $types = array_unique(array_map(function($menu) {
            return isset($menu['type']) ? 'filter-' . strtolower(trim($menu['type'])) : '';
        }, $menus));
        
        return $this->render('menuFirebase/showw.html.twig', [
            'menus' => $menus,
            'types' => $types
        ]);
    }

    #[Route('/', name: 'front_index', methods: ['GET', 'POST'])]
    public function index(Request $request, FirebaseService $firebase): Response
    {
        $user = $request->getSession()->get('user');
        
        if ($request->isMethod('POST')) {
            if (!$user || $user['type'] !== 'client') {
                $this->addFlash('error', 'Vous devez être connecté pour réserver');
                return $this->redirectToRoute('app_login');
            }
            
            $firebase->createTable([
                'name' => $request->request->get('name'),
                'email' => $request->request->get('email'),
                'tel' => $request->request->get('phone'),
                'date' => $request->request->get('date'),
                'time' => $request->request->get('time'),
                'numberPeople' => $request->request->get('people'),
                'message' => $request->request->get('message'),
                'subject' => $request->request->get('subject'),
            ]);
            
            $this->addFlash('success', 'Réservation enregistrée !');
            return $this->redirectToRoute('front_index');
        }
        
        $menus = $firebase->getAllMenus();
        $types = array_unique(array_map(function($menu) {
            return isset($menu['type']) ? 'filter-' . strtolower(trim($menu['type'])) : '';
        }, $menus));
        
        return $this->render('front/front.html.twig', [
            'menus' => $menus,
            'types' => $types,
            'specials' => $firebase->getAllSpecials(),
            'chefs' => $firebase->getAllChefs(),
            'contacts' => $firebase->getAllContacts(),
            'galleries' => $firebase->getAllGalleries(),
            'partties' => $firebase->getAllPartties(),
            'user' => $user // Toujours passer user même si null
        ]);
    }
}