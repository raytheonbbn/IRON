// IRON: iron_headers
/*
 * Distribution A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
 * DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
 * Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contracts No. HR0011-15-C-0097 and
 * HR0011-17-C-0050. Any opinions, findings and conclusions or
 * recommendations expressed in this material are those of the author(s)
 * and do not necessarily reflect the views of the Defense Advanced
 * Research Project Agency.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* IRON: end */

/// \brief The IRON callback header file.
///
/// Provides the IRON software with a simple, flexible, object-oriented
/// callback capability.  Callback methods may include zero, one, two, or
/// three arguments.

#ifndef IRON_COMMON_CALLBACK_H
#define IRON_COMMON_CALLBACK_H

#include <stdlib.h>


namespace iron
{

  /// \brief The abstract base class for all callback objects.
  ///
  /// This interface implements the callback "springboard", converting a
  /// single, common form of object-oriented callback into a user-defined form
  /// of object-oriented callback.  The user implements child classes of this
  /// abstract base class using the CallbackNoArg, CallbackOneArg,
  /// CallbackTwoArg, and CallbackThreeArg C++ templates.  Do NOT attempt to
  /// create your own child class manually!
  class CallbackInterface
  {

   public:

    /// \brief The callback interface destructor.
    ///
    /// This abstract class MUST have a virtual destructor in order for child
    /// classes to be destroyed properly.
    virtual ~CallbackInterface()
    { }

    /// \brief The method that is called to initiate the callback.
    ///
    /// This method must be implemented by the child classes, which are
    /// created using the Callback*Arg templates.  When called, the child
    /// class does its callback using its stored object, method, and
    /// arguments.  Note that there is no return value.
    virtual void PerformCallback() = 0;

    /// \brief The method that is called to copy the callback object.
    ///
    /// This method must be implemented by the child classes, which are
    /// created using the Callback*Arg templates.  It allows a service that
    /// uses callbacks to make copies of these objects.  It is needed to
    /// return the proper base class type.
    ///
    /// \return  A pointer to a copy of this object.
    virtual CallbackInterface* Clone() = 0;

    /// \brief The method that is called to release a callback object copy.
    ///
    /// This method allows a service that uses callbacks to release copies of
    /// objects created using the Clone() method.  Call this method on the
    /// object returned by the Clone() method, then let go of the pointer.
    virtual void ReleaseClone() = 0;

  }; // end class CallbackInterface


  /// \brief The template for a callback having no arguments.
  ///
  /// This template is used to create CallbackInterface child classes for
  /// callbacks that require no arguments.
  ///
  /// Here is an example of code that creates a callback that takes no
  /// arguments.  The Target class will receive the callback to its
  /// ReceiveCallback() method.  The callback object is passed to a Service
  /// class that will perform the callback when appropriate by calling
  /// PerformCallback() on the object.
  ///
  /// \code
  /// class Target
  /// {
  /// public:
  ///   void ReceiveCallback() { ... }
  ///   ...
  /// };
  ///
  /// class Service
  /// {
  /// public:
  ///   void RegisterCallback(CallbackInterface* cb)
  ///   {
  ///     // Call cb->Clone() and store the cloned callback object.
  ///     StoreCallback(cb->Clone());
  ///   }
  ///   void Run()
  ///   {
  ///     CallbackInterface*  cb = GetNextCallback();
  ///     cb->PerformCallback();
  ///     cb->ReleaseClone();
  ///     cb = NULL;
  ///   }
  ///   ...
  /// };
  ///
  /// int main()
  /// {
  ///   Target                 my_target;
  ///   Service                my_service;
  ///   CallbackNoArg<Target>  cb(&my_target, &Target::ReceiveCallback);
  ///   my_service.RegisterCallback(&cb);
  ///   my_service.Run();
  ///   ...
  /// }
  /// \endcode
  ///
  /// \tparam  T  The class that is to receive the callback.
  template<class T>
  class CallbackNoArg : public CallbackInterface
  {

   public:

    /// \brief The constructor.
    ///
    /// \param  instance  The class instance that will receive the callback.
    /// \param  method    The class method that will be called for the
    ///                   callback.
    CallbackNoArg(T* instance, void (T::*method)())
        : instance_(instance), method_(method), next_(NULL)
    { }

    /// \brief The copy constructor.
    ///
    /// \param  cb  The object to be copied.
    CallbackNoArg(const CallbackNoArg<T>& cb)
        : instance_(cb.instance_), method_(cb.method_), next_(NULL)
    { }

    /// \brief The destructor.
    ///
    /// Since this object only contains copyable objects or pointers to
    /// non-copyable objects, there is nothing to be done for cleanup.
    virtual ~CallbackNoArg()
    { }

    /// \brief The method that is called to initiate the callback.
    ///
    /// When this method is called, the class does its callback using its
    /// stored object, method, and arguments.  Note that there is no return
    /// value.
    virtual void PerformCallback()
    {
      (instance_->*method_)();
    }

    /// \brief The method that is called to copy the callback object.
    ///
    /// This method allows a service that uses callbacks to make copies of
    /// these objects.  The returned object must be released using the
    /// ReleaseClone() method.
    ///
    /// \return  A pointer to a copy of this object.
    virtual CallbackInterface* Clone()
    {
      if (pool_ == NULL)
      {
        return new CallbackNoArg<T>(*this);
      }

      CallbackNoArg<T>*  cb = pool_;
      pool_                 = cb->next_;

      cb->instance_ = instance_;
      cb->method_   = method_;
      cb->next_     = NULL;

      return cb;
    }

    /// \brief The method that is called to release a callback object copy.
    ///
    /// This method allows a service that uses callbacks to release copies of
    /// objects created using the Clone() method.  Call this method on the
    /// object returned by the Clone() method, then let go of the pointer.
    virtual void ReleaseClone()
    {
      next_ = pool_;
      pool_ = this;
    }

    /// \brief Empty the internal copy pool.
    ///
    /// This static method should be called after all services (such as the
    /// Timer class) have released all of the cloned objects (by canceling all
    /// of the timers using the callback type), and before the process exits,
    /// in order for all allocated memory in the internal pool to be freed.
    static void EmptyPool()
    {
      while (pool_ != NULL)
      {
        CallbackNoArg<T>* cb = pool_;
        pool_                = cb->next_;
        delete cb;
      }
    }

   private:

    /// A pointer to the callback object instance.
    T*  instance_;

    /// A method pointer to the callback class method.
    void  (T::*method_)();

    /// A pointer to the next element in the pool.
    CallbackNoArg<T>*  next_;

    /// A common pointer to the pool.
    static CallbackNoArg<T>*  pool_;

  }; // end class CallbackNoArg

  template<class T>
  CallbackNoArg<T>* CallbackNoArg<T>::pool_ = NULL;


  /// \brief The template for a callback having one argument.
  ///
  /// This template is used to create CallbackInterface child classes for
  /// callbacks that require one argument.  Note that if the argument is not
  /// copyable or the user does not want to copy the argument, then one must
  /// use a pointer in the argument type definition.  The argument should
  /// never be a reference since this template reuses objects in the Clone()
  /// method and references cannot be "copied" like pointers can.
  ///
  /// See the description for the CallbackThreeArg template for examples on
  /// how to use this template.  Substitute in CallbackOneArg and only specify
  /// a single argument.
  ///
  /// \tparam  T   The class that is to receive the callback.
  /// \tparam  A1  The type for the first argument in the callback.  May be a
  ///              pointer, but must never be a reference.
  template<class T, class A1>
  class CallbackOneArg : public CallbackInterface
  {

   public:

    /// \brief The constructor.
    ///
    /// \param  instance  The class instance that will receive the callback.
    /// \param  method    The class method that will be called for the
    ///                   callback.
    /// \param  arg1      The first argument that will be passed to the
    ///                   callback.
    CallbackOneArg(T* instance, void (T::*method)(A1 arg1), A1 arg1)
        : instance_(instance), method_(method), arg1_(arg1), next_(NULL)
    { }

    /// \brief The copy constructor.
    ///
    /// \param  cb  The object to be copied.
    CallbackOneArg(const CallbackOneArg<T, A1>& cb)
        : instance_(cb.instance_), method_(cb.method_), arg1_(cb.arg1_),
          next_(NULL)
    { }

    /// \brief The destructor.
    ///
    /// Since this object only contains copyable objects or pointers to
    /// non-copyable objects, there is nothing to be done for cleanup.
    virtual ~CallbackOneArg()
    { }

    /// \brief The method that is called to initiate the callback.
    ///
    /// When this method is called, the class does its callback using its
    /// stored object, method, and arguments.  Note that there is no return
    /// value.
    virtual void PerformCallback()
    {
      (instance_->*method_)(arg1_);
    }

    /// \brief The method that is called to copy the callback object.
    ///
    /// This method allows a service that uses callbacks to make copies of
    /// these objects.  The returned object must be released using the
    /// ReleaseClone() method.
    ///
    /// \return  A pointer to a copy of this object.
    virtual CallbackInterface* Clone()
    {
      if (pool_ == NULL)
      {
        return new CallbackOneArg<T, A1>(*this);
      }

      CallbackOneArg<T, A1>*  cb = pool_;
      pool_                      = cb->next_;

      cb->instance_ = this->instance_;
      cb->method_   = method_;
      cb->arg1_     = arg1_;
      cb->next_     = NULL;

      return cb;
    }

    /// \brief The method that is called to release a callback object copy.
    ///
    /// This method allows a service that uses callbacks to release copies of
    /// objects created using the Clone() method.  Call this method on the
    /// cloned object.
    virtual void ReleaseClone()
    {
      next_ = pool_;
      pool_ = this;
    }

    /// \brief Empty the internal copy pool.
    ///
    /// This static method should be called after all services (such as the
    /// Timer class) have released all of the cloned objects (by canceling all
    /// of the timers using the callback type), and before the process exits,
    /// in order for all allocated memory in the internal pool to be freed.
    static void EmptyPool()
    {
      while (pool_ != NULL)
      {
        CallbackOneArg<T, A1>* cb = pool_;
        pool_                     = cb->next_;
        delete cb;
      }
    }

   private:

    /// A pointer to the callback object instance.
    T*  instance_;

    /// A method pointer to the callback class method.
    void  (T::*method_)(A1 arg1);

    /// The first argument to be passed into the callback method.
    A1  arg1_;

    /// A pointer to the next element in the pool.
    CallbackOneArg<T, A1>*  next_;

    /// A common pointer to the pool.
    static CallbackOneArg<T, A1>*  pool_;

  }; // end class CallbackOneArg

  template<class T, class A1>
  CallbackOneArg<T, A1>* CallbackOneArg<T, A1>::pool_ = NULL;


  /// \brief The template for a callback having two arguments.
  ///
  /// This template is used to create CallbackInterface child classes for
  /// callbacks that require two arguments.  Note that if an argument is not
  /// copyable or the user does not want to copy an argument, then one must
  /// use a pointer in the argument type definition.  The arguments should
  /// never be references since this template reuses objects in the Clone()
  /// method and references cannot be "copied" like pointers can.
  ///
  /// See the description for the CallbackThreeArg template for examples on
  /// how to use this template.  Substitute in CallbackTwoArg and only specify
  /// two arguments.
  ///
  /// \tparam  T   The class that is to receive the callback.
  /// \tparam  A1  The type for the first argument in the callback.  May be a
  ///              pointer, but must never be a reference.
  /// \tparam  A2  The type for the second argument in the callback.  May be a
  ///              pointer, but must never be a reference.
  template<class T, class A1, class A2>
  class CallbackTwoArg : public CallbackInterface
  {

   public:

    /// \brief The constructor.
    ///
    /// \param  instance  The class instance that will receive the callback.
    /// \param  method    The class method that will be called for the
    ///                   callback.
    /// \param  arg1      The first argument that will be passed to the
    ///                   callback.
    /// \param  arg2      The second argument that will be passed to the
    ///                   callback.
    CallbackTwoArg(T* instance, void (T::*method)(A1 arg1, A2 arg2), A1 arg1,
                   A2 arg2)
        : instance_(instance), method_(method), arg1_(arg1), arg2_(arg2),
          next_(NULL)
    { }

    /// \brief The copy constructor.
    ///
    /// \param  cb  The object to be copied.
    CallbackTwoArg(const CallbackTwoArg<T, A1, A2>& cb)
        : instance_(cb.instance_), method_(cb.method_), arg1_(cb.arg1_),
          arg2_(cb.arg2_), next_(NULL)
    { }

    /// \brief The destructor.
    ///
    /// Since this object only contains copyable objects or pointers to
    /// non-copyable objects, there is nothing to be done for cleanup.
    virtual ~CallbackTwoArg()
    { }

    /// \brief The method that is called to initiate the callback.
    ///
    /// When this method is called, the class does its callback using its
    /// stored object, method, and arguments.  Note that there is no return
    /// value.
    virtual void PerformCallback()
    {
      (instance_->*method_)(arg1_, arg2_);
    }

    /// \brief The method that is called to copy the callback object.
    ///
    /// This method allows a service that uses callbacks to make copies of
    /// these objects.  The returned object must be released using the
    /// ReleaseClone() method.
    ///
    /// \return  A pointer to a copy of this object.
    virtual CallbackInterface* Clone()
    {
      if (pool_ == NULL)
      {
        return new CallbackTwoArg<T, A1, A2>(*this);
      }

      CallbackTwoArg<T, A1, A2>*  cb = pool_;
      pool_                          = cb->next_;

      cb->instance_ = this->instance_;
      cb->method_   = method_;
      cb->arg1_     = arg1_;
      cb->arg2_     = arg2_;
      cb->next_     = NULL;

      return cb;
    }

    /// \brief The method that is called to release a callback object copy.
    ///
    /// This method allows a service that uses callbacks to release copies of
    /// objects created using the Clone() method.  Call this method on the
    /// cloned object.
    virtual void ReleaseClone()
    {
      next_ = pool_;
      pool_ = this;
    }

    /// \brief Empty the internal copy pool.
    ///
    /// This static method should be called after all services (such as the
    /// Timer class) have released all of the cloned objects (by canceling all
    /// of the timers using the callback type), and before the process exits,
    /// in order for all allocated memory in the internal pool to be freed.
    static void EmptyPool()
    {
      while (pool_ != NULL)
      {
        CallbackTwoArg<T, A1, A2>* cb = pool_;
        pool_                         = cb->next_;
        delete cb;
      }
    }

   private:

    /// A pointer to the callback object instance.
    T*  instance_;

    /// A method pointer to the callback class method.
    void  (T::*method_)(A1 arg1, A2 arg2);

    /// The first argument to be passed into the callback method.
    A1  arg1_;

    /// The second argument to be passed into the callback method.
    A2  arg2_;

    /// A pointer to the next element in the pool.
    CallbackTwoArg<T, A1, A2>*  next_;

    /// A common pointer to the pool.
    static CallbackTwoArg<T, A1, A2>*  pool_;

  }; // end class CallbackTwoArg

  template<class T, class A1, class A2>
  CallbackTwoArg<T, A1, A2>* CallbackTwoArg<T, A1, A2>::pool_ = NULL;


  /// \brief The template for a callback having three arguments.
  ///
  /// This template is used to create CallbackInterface child classes for
  /// callbacks that require three arguments.  Note that if an argument is not
  /// copyable or the user does not want to copy an argument, then one must
  /// use a pointer in the argument type definition.  The arguments should
  /// never be references since this template reuses objects in the Clone()
  /// method and references cannot be "copied" like pointers can.
  ///
  /// Here is an example of code that creates a callback that takes three
  /// arguments.  The Target class will receive the callback to its
  /// ReceiveCallback() method.  The callback object is passed to a Service
  /// class that will perform the callback when appropriate by calling
  /// PerformCallback() on the object.
  ///
  /// \code
  /// class Target
  /// {
  /// public:
  ///   void ReceiveCallback(CopyableItem arg1,
  ///                        NonCopyableItem* arg2,
  ///                        int arg3) { ... }
  ///   ...
  /// };
  ///
  /// class Service
  /// {
  /// public:
  ///   void RegisterCallback(CallbackInterface* cb)
  ///   {
  ///     // Call cb->Clone() and store the cloned callback object.
  ///     StoreCallback(cb->Clone());
  ///   }
  ///   void Run()
  ///   {
  ///     CallbackInterface*  cb = GetNextCallback();
  ///     cb->PerformCallback();
  ///     cb->ReleaseClone();
  ///     cb = NULL;
  ///   }
  ///   ...
  /// };
  ///
  /// int main()
  /// {
  ///   Target                 my_target;
  ///   Service                my_service;
  ///   NonCopyableItem        nci_arg;
  ///   {
  ///     CopyableItem           ci_arg;
  ///     CallbackThreeArg<Target, CopyableItem, NonCopyableItem*, int>  cb(
  ///       &my_target, &Target::ReceiveCallback, ci_arg, &nci_arg, 42);
  ///     my_service.RegisterCallback(&cb);
  ///   }
  ///   // Note that ci_arg and cb are now out of scope here.
  ///   // Note that nci_arg must be owned outside of the callback object.
  ///   my_service.Run();
  ///   ...
  /// }
  /// \endcode
  ///
  /// Note how the callback object and copyable argument object may go out of
  /// scope after the callback is registered with the service.  This works
  /// because the service clones the callback object and the callback object
  /// copies the argument.
  ///
  /// Note that if a non-copyable argument needs to be used, then a pointer to
  /// the non-copyable argument needs to be specified to the callback template
  /// and constructor.  This is demonstrated in the code above.
  ///
  /// \tparam  T   The class that is to receive the callback.
  /// \tparam  A1  The type for the first argument in the callback.  May be a
  ///              pointer, but must never be a reference.
  /// \tparam  A2  The type for the second argument in the callback.  May be a
  ///              pointer, but must never be a reference.
  /// \tparam  A3  The type for the third argument in the callback.  May be a
  ///              pointer, but must never be a reference.
  template<class T, class A1, class A2, class A3>
  class CallbackThreeArg : public CallbackInterface
  {

   public:

    /// \brief The constructor.
    ///
    /// \param  instance  The class instance that will receive the callback.
    /// \param  method    The class method that will be called for the
    ///                   callback.
    /// \param  arg1      The first argument that will be passed to the
    ///                   callback.
    /// \param  arg2      The second argument that will be passed to the
    ///                   callback.
    /// \param  arg3      The third argument that will be passed to the
    ///                   callback.
    CallbackThreeArg(T* instance,
                     void (T::*method)(A1 arg1, A2 arg2, A3 arg3),
                     A1 arg1, A2 arg2, A3 arg3)
        : instance_(instance), method_(method), arg1_(arg1), arg2_(arg2),
          arg3_(arg3), next_(NULL)
    { }

    /// \brief The copy constructor.
    ///
    /// \param  cb  The object to be copied.
    CallbackThreeArg(const CallbackThreeArg<T, A1, A2, A3>& cb)
        : instance_(cb.instance_), method_(cb.method_), arg1_(cb.arg1_),
          arg2_(cb.arg2_), arg3_(cb.arg3_), next_(NULL)
    { }

    /// \brief The destructor.
    ///
    /// Since this object only contains copyable objects or pointers to
    /// non-copyable objects, there is nothing to be done for cleanup.
    virtual ~CallbackThreeArg()
    { }

    /// \brief The method that is called to initiate the callback.
    ///
    /// When this method is called, the class does its callback using its
    /// stored object, method, and arguments.  Note that there is no return
    /// value.
    virtual void PerformCallback()
    {
      (instance_->*method_)(arg1_, arg2_, arg3_);
    }

    /// \brief The method that is called to copy the callback object.
    ///
    /// This method allows a service that uses callbacks to make copies of
    /// these objects.  The returned object must be released using the
    /// ReleaseClone() method.
    ///
    /// \return  A pointer to a copy of this object.
    virtual CallbackInterface* Clone()
    {
      if (pool_ == NULL)
      {
        return new CallbackThreeArg<T, A1, A2, A3>(*this);
      }

      CallbackThreeArg<T, A1, A2, A3>*  cb = pool_;
      pool_                                = cb->next_;

      cb->instance_ = instance_;
      cb->method_   = method_;
      cb->arg1_     = arg1_;
      cb->arg2_     = arg2_;
      cb->arg3_     = arg3_;
      cb->next_     = NULL;

      return cb;
    }

    /// \brief The method that is called to release a callback object copy.
    ///
    /// This method allows a service that uses callbacks to release copies of
    /// objects created using the Clone() method.  Call this method on the
    /// cloned object.
    virtual void ReleaseClone()
    {
      next_ = pool_;
      pool_ = this;
    }

    /// \brief Empty the internal copy pool.
    ///
    /// This static method should be called after all services (such as the
    /// Timer class) have released all of the cloned objects (by canceling all
    /// of the timers using the callback type), and before the process exits,
    /// in order for all allocated memory in the internal pool to be freed.
    static void EmptyPool()
    {
      while (pool_ != NULL)
      {
        CallbackThreeArg<T, A1, A2, A3>* cb = pool_;
        pool_                               = cb->next_;
        delete cb;
      }
    }

   private:

    /// A pointer to the callback object instance.
    T*  instance_;

    /// A method pointer to the callback class method.
    void  (T::*method_)(A1 arg1, A2 arg2, A3 arg3);

    /// The first argument to be passed into the callback method.
    A1  arg1_;

    /// The second argument to be passed into the callback method.
    A2  arg2_;

    /// The third argument to be passed into the callback method.
    A3  arg3_;

    /// A pointer to the next element in the pool.
    CallbackThreeArg<T, A1, A2, A3>*  next_;

    /// A common pointer to the pool.
    static CallbackThreeArg<T, A1, A2, A3>*  pool_;

  }; // end class CallbackThreeArg

  template<class T, class A1, class A2, class A3>
  CallbackThreeArg<T, A1, A2, A3>*
  CallbackThreeArg<T, A1, A2, A3>::pool_ = NULL;

} // namespace iron

#endif // IRON_COMMON_CALLBACK_H
